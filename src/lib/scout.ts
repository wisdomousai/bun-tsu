// The scout: reads a project and reports findings. Read-only; never prints secret values.
import { existsSync, readdirSync } from "node:fs";
import { join, resolve } from "node:path";
import { classify, imitates, POPULAR } from "./classify.ts";
import { knownBad } from "./knownbad.ts";

export type Severity = "critical" | "high" | "medium" | "low" | "info";
export type Finding = { severity: Severity; category: string; vector: string; types: string[]; subject: string; detail: string; fix: string; imitates?: string; url?: string };
export type Report = { project: string; dir: string; lockfiles: string[]; declared: Record<string, number>; installed: number; resolved: number; audit: string; profile: Record<string, string[]>; findings: Finding[] };

const VECTOR: Record<string, string> = {
  "known-compromise": "malicious-update", "shady-install-script": "install-script", "trusted-install-script": "install-script", "install-scripts": "install-script",
  "trusted-deps": "install-script", "shady-script": "install-script", "committed-token": "leaked-secrets", "env-unignored": "leaked-secrets",
  "no-lockfile": "version-drift", "loose-ranges": "version-drift", "wild-version": "version-drift", "multiple-lockfiles": "version-drift", "binary-lockfile": "version-drift",
  "typosquat-suspect": "typosquat", "remote-source": "remote-source", "deprecated": "maintainer-takeover", "known-vuln": "known-vuln",
  "dependency-confusion-risk": "dependency-confusion", "not-installed": "general",
};
const LIFECYCLE = ["preinstall", "install", "postinstall", "prepare", "prepublish", "preprepare"];
const SHADY = /(curl|wget)\b.*\|\s*(ba)?sh|\beval\b|base64\s+-d|node\s+-e|bun\s+-e|powershell|Invoke-WebRequest|\bnc\b\s/i;
const ORDER: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

const readText = (p: string) => { try { return require("node:fs").readFileSync(p, "utf8") as string; } catch { return null; } };
const readJSON = (p: string) => { const t = readText(p); try { return t ? JSON.parse(t) : null; } catch { return null; } };
const readJSONC = (p: string) => { const t = readText(p); try { return t ? JSON.parse(t.replace(/,(\s*[}\]])/g, "$1")) : null; } catch { return null; } };

/** name -> exact resolved versions, from bun.lock or package-lock.json */
export function resolvedVersions(dir: string): Map<string, Set<string>> {
  const out = new Map<string, Set<string>>();
  const put = (n: string, v: string) => { if (!out.has(n)) out.set(n, new Set()); out.get(n)!.add(v); };
  const bunLock = readJSONC(join(dir, "bun.lock"));
  for (const entry of Object.values<any>(bunLock?.packages ?? {})) {
    const id = Array.isArray(entry) ? entry[0] : undefined;
    const at = typeof id === "string" ? id.lastIndexOf("@") : -1;
    if (at > 0) put(id.slice(0, at), id.slice(at + 1));
  }
  const npmLock = readJSON(join(dir, "package-lock.json"));
  for (const [path, meta] of Object.entries<any>(npmLock?.packages ?? {})) {
    if (!path || !meta?.version) continue;
    put(meta.name ?? path.split("node_modules/").pop(), meta.version);
  }
  return out;
}

export async function scout(dirArg = ".", opts: { audit?: boolean } = {}): Promise<Report> {
  const dir = resolve(dirArg);
  const pkg = readJSON(join(dir, "package.json"));
  if (!pkg) throw new Error(`No readable package.json in ${dir}`);
  const findings: Finding[] = [];
  const add = (severity: Severity, category: string, subject: string, detail: string, fix: string, extra: Partial<Finding> = {}) =>
    findings.push({ severity, category, vector: VECTOR[category] ?? "general", types: [], subject, detail, fix, ...extra });

  // Lockfiles
  const locks = ["bun.lock", "bun.lockb", "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "npm-shrinkwrap.json"].filter(f => existsSync(join(dir, f)));
  if (!locks.length) add("high", "no-lockfile", "project", "No lockfile found; every install may resolve different code.", "Run `bun install`, commit bun.lock, and use `bun install --frozen-lockfile` in CI.");
  if (locks.length > 1) add("low", "multiple-lockfiles", locks.join(", "), "Several package managers' lockfiles coexist and can drift apart.", "Pick one package manager and delete the other lockfiles.");
  if (locks.includes("bun.lockb") && !locks.includes("bun.lock")) add("info", "binary-lockfile", "bun.lockb", "Binary lockfile can't be reviewed in diffs.", "Run `bun install --save-text-lockfile` to migrate to the text bun.lock.");

  // Declared dependencies
  const declared: Record<string, string> = {};
  const stats = { total: 0, pinned: 0, ranged: 0, wild: 0, remote: 0, local: 0 };
  for (const g of ["dependencies", "devDependencies", "optionalDependencies", "peerDependencies"])
    for (const [name, spec] of Object.entries<string>(pkg[g] ?? {})) {
      declared[name] = spec; stats.total++;
      const s = String(spec).trim();
      if (["", "*", "latest", "next"].includes(s) || /^x(\.x)*$/i.test(s)) { stats.wild++; add("high", "wild-version", name, `Version "${s}" in ${g} accepts any future release, including a hijacked one.`, `Pin ${name} to a known version.`); }
      else if (/^(git\+|git:|github:|gitlab:|bitbucket:|https?:)/.test(s) || /^[\w.-]+\/[\w.-]+(#.*)?$/.test(s)) { stats.remote++; add("medium", "remote-source", name, `Installed from "${s}", bypassing the registry; branch refs can change silently.`, "Use a registry release, or pin to a full commit SHA."); }
      else if (/^(file:|link:|workspace:|\.{0,2}\/)/.test(s)) stats.local++;
      else if (/^[\^~><=]/.test(s) || /\|\||\s-\s/.test(s)) stats.ranged++;
      else stats.pinned++;
    }
  if (stats.total && stats.ranged / stats.total > 0.8 && !locks.length)
    add("medium", "loose-ranges", "project", `${stats.ranged}/${stats.total} deps use ranges with no lockfile to hold them.`, "Commit a lockfile; consider exact versions for critical deps.");

  // Typosquats
  for (const name of Object.keys(declared)) {
    const near = imitates(name);
    if (near) add("high", "typosquat-suspect", name, `Name is one edit away from the popular package "${near}".`, `Confirm ${name} is intended (registry page, maintainer, downloads); otherwise replace it with ${near}.`, { imitates: near });
  }

  // Project scripts
  for (const [k, v] of Object.entries<string>(pkg.scripts ?? {})) if (SHADY.test(v))
    add(LIFECYCLE.includes(k) ? "high" : "medium", "shady-script", `scripts.${k}`, `Script runs remote or obfuscated code: \`${v.slice(0, 120)}\``, "Replace with a vendored, reviewed script.");

  // Resolved versions vs. known compromises
  const resolved = resolvedVersions(dir);
  const nm = join(dir, "node_modules");
  const trusted = new Set<string>(pkg.trustedDependencies ?? []);
  if (trusted.size) add("info", "trusted-deps", [...trusted].join(", "), `${trusted.size} package(s) allowed by Bun to run lifecycle scripts.`, "Re-review this list on each upgrade; remove entries that no longer need native builds.");
  let installed = 0; const scripted: string[] = []; const nativeInstalled = new Set<string>();
  if (existsSync(nm)) {
    const dirs: [string, string][] = [];
    for (const e of readdirSync(nm)) {
      if (e.startsWith(".")) continue;
      const p = join(nm, e);
      if (e.startsWith("@")) { try { for (const s of readdirSync(p)) dirs.push([`${e}/${s}`, join(p, s)]); } catch {} }
      else dirs.push([e, p]);
    }
    for (const [name, p] of dirs) {
      const m = readJSON(join(p, "package.json")); if (!m) continue; installed++;
      if (m.version) { if (!resolved.has(name)) resolved.set(name, new Set()); resolved.get(name)!.add(m.version); }
      const hooks = LIFECYCLE.filter(h => m.scripts?.[h]);
      if (existsSync(join(p, "binding.gyp")) || m.gypfile || /gyp|prebuild/.test(JSON.stringify(m.scripts ?? {}))) nativeInstalled.add(name);
      if (hooks.length) scripted.push(name);
      if (hooks.length && SHADY.test(hooks.map(h => m.scripts[h]).join(" ")))
        add("critical", "shady-install-script", name, `Installed package's ${hooks.join("/")} script downloads or evals code.`, `Remove ${name} from trustedDependencies (if present), inspect it, and rotate credentials on machines that ran it.`);
      else if (hooks.length && trusted.has(name))
        add("low", "trusted-install-script", name, `Has ${hooks.join("/")} and is in trustedDependencies, so it runs on install.`, "Fine if it builds native code you need; verify on upgrades.");
      if (m.deprecated) add("medium", "deprecated", name, `Marked deprecated: ${String(m.deprecated).slice(0, 100)}`, `Find the maintained successor to ${name}.`);
    }
    if (scripted.length) add("info", "install-scripts", scripted.slice(0, 15).join(", ") + (scripted.length > 15 ? ` (+${scripted.length - 15})` : ""), `${scripted.length} installed package(s) declare lifecycle scripts. Bun skips these unless trusted (or on its default allowlist).`, "Trust only what genuinely needs to build.");
  } else add("info", "not-installed", "node_modules", "Dependencies not installed; install-script checks skipped.", "Run `bun install`, then consult Bun Tsu again for a deeper reading.");

  let resolvedCount = 0;
  for (const [name, versions] of resolved) for (const v of versions) {
    resolvedCount++;
    const hit = knownBad(name, v);
    if (hit) add("critical", "known-compromise", `${name}@${v}`, `This exact version was published by an attacker (${hit.incident}).`, `Remove ${name}@${v}, reinstall a clean version, rotate any secrets on machines or builds that ran it, and rebuild bundles.`, { url: hit.url });
  }

  // Secrets hygiene (never print values)
  const npmrc = readText(join(dir, ".npmrc")) ?? "";
  const bunfig = readText(join(dir, "bunfig.toml")) ?? "";
  if (/_authToken\s*=\s*(?!\$\{)\S/.test(npmrc)) add("critical", "committed-token", ".npmrc", "Contains a literal registry auth token.", "Revoke it, reference `${NPM_TOKEN}` instead, and scrub git history.");
  if (/token\s*=\s*"(?!\$)[^"]+"/i.test(bunfig)) add("critical", "committed-token", "bunfig.toml", "Contains a literal registry token.", "Use `$NPM_TOKEN`-style env references and revoke the token.");
  const gi = readText(join(dir, ".gitignore")) ?? "";
  for (const f of [".env", ".env.local", ".env.production"]) if (existsSync(join(dir, f)) && !/^\s*\/?\.env/m.test(gi))
    add("high", "env-unignored", f, `${f} exists and .gitignore doesn't exclude .env files.`, "Add `.env*` to .gitignore; if it was ever committed, rotate those secrets.");

  // Purpose profile
  const profile: Record<string, string[]> = {}; const ptypes: Record<string, string[]> = {};
  for (const name of Object.keys(declared)) { const t = classify(name, { native: nativeInstalled.has(name) }); ptypes[name] = t; for (const x of t.length ? t : ["other"]) (profile[x] ??= []).push(name); }

  // Dependency confusion hint
  const custom = (npmrc + "\n" + bunfig).split("\n").some(l => /registry\s*=/.test(l) && !/registry\.npmjs\.org/.test(l));
  if (custom) {
    const unscoped = Object.keys(declared).filter(n => !n.startsWith("@") && !POPULAR.includes(n) && !ptypes[n].length);
    if (unscoped.length) add("low", "dependency-confusion-risk", unscoped.slice(0, 10).join(", "), `A custom registry is configured and ${unscoped.length} unscoped, unrecognised dependency name(s) exist; if any are internal, a public package of the same name could be preferred.`, "Move internal packages under an org scope (@yourorg/...) mapped to your registry, and claim that scope on npm.");
  }

  // Optional audit via bun
  let audit = "skipped (pass --audit)";
  if (opts.audit) {
    try {
      const p = Bun.spawnSync(["bun", "audit", "--json"], { cwd: dir, stdout: "pipe", stderr: "ignore" });
      const j = JSON.parse(p.stdout.toString() || "{}"); let n = 0;
      for (const [name, list] of Object.entries<any>(j)) for (const a of (Array.isArray(list) ? list : [list])) {
        if (!a || typeof a !== "object") continue; n++;
        const sev = String(a.severity ?? "medium").toLowerCase().replace("moderate", "medium") as Severity;
        add(ORDER[sev] !== undefined ? sev : "medium", "known-vuln", name, a.title ?? "Known advisory", `Upgrade ${name} to a patched version.`, { url: a.url });
      }
      audit = `bun audit: ${n} advisory record(s)`;
    } catch { audit = "bun audit: unavailable or unparseable"; }
  }

  for (const f of findings) {
    const sub = f.subject.split("@").slice(0, f.subject.startsWith("@") ? 2 : 1).join("@");
    f.types = f.imitates ? classify(f.imitates) : ptypes[sub] ?? classify(sub);
  }
  findings.sort((a, b) => ORDER[a.severity] - ORDER[b.severity]);
  return { project: pkg.name ?? dir, dir, lockfiles: locks, declared: stats, installed, resolved: resolvedCount, audit, profile, findings };
}
