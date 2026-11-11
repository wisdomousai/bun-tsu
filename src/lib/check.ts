// Checks package specs before they are installed: the `check` command and the agent hook.
import { imitates, classify } from "./classify.ts";
import { knownBad } from "./knownbad.ts";
import { osv, packument, pool, socket, socketFinding, weeklyDownloads } from "./registry.ts";
import { resolveSpec, signals } from "./signals.ts";
import { VECTOR, ORDER, type Finding, type Severity } from "./scout.ts";

export type Verdict = "block" | "ask" | "note" | "ok";
export type Checked = { spec: string; name: string; version?: string; verdict: Verdict; findings: Finding[] };

const BLOCK = new Set(["known-compromise", "malicious-package", "unknown-package", "socket-malware", "socket-block"]);
const LOCAL = /^(\.{0,2}\/|~|file:|link:|workspace:)/;
const REMOTE = /^(git\+|git:|github:|gitlab:|bitbucket:|https?:)|^[\w.-]+\/[\w.-]+(#.*)?$/;

/** "zod@^3", "@scope/x@1.2.3", "alias@npm:real@2" -> name and range. Undefined for local paths. */
export function parseSpec(spec: string): { name: string; range: string } | { remote: string } | undefined {
  if (LOCAL.test(spec)) return;
  if (REMOTE.test(spec) && !spec.startsWith("@")) return { remote: spec };
  const at = spec.indexOf("@", 1);
  const name = at > 0 ? spec.slice(0, at) : spec, range = at > 0 ? spec.slice(at + 1) : "latest";
  if (range.startsWith("npm:")) return parseSpec(range.slice(4));
  if (REMOTE.test(range)) return { remote: spec };
  return { name, range };
}

export async function check(specs: string[], opts: { customRegistry?: boolean } = {}): Promise<Checked[]> {
  const out: Checked[] = [];
  await pool([...new Set(specs)], 6, async spec => {
    const parsed = parseSpec(spec);
    if (!parsed) return;
    const findings: Finding[] = [];
    const add = (severity: Severity, category: string, subject: string, detail: string, fix: string, extra: Partial<Finding> = {}) =>
      findings.push({ severity, category, vector: VECTOR[category] ?? "general", types: [], subject, detail, fix, ...extra });
    if ("remote" in parsed) {
      add("medium", "remote-source", spec, `${spec} installs from git or a URL, bypassing the registry; branch refs can change silently.`, "Use a registry release, or pin to a full commit SHA.");
      out.push({ spec, name: spec, verdict: "ask", findings });
      return;
    }
    const { name, range } = parsed;
    const near = imitates(name);
    if (near) add("high", "typosquat-suspect", name, `Name is one edit away from the popular package "${near}".`, `Use ${near} unless ${name} is really what you meant.`, { imitates: near });

    const p = await packument(name);
    let version: string | undefined = /^\d+\.\d+\.\d+/.test(range) ? range : undefined;
    if (p === "missing") {
      if (opts.customRegistry) add("info", "unclaimed-name", name, `${name} isn't on public npm; fine if your private registry serves it.`, `Keep internal packages under an org scope you own on npm.`);
      else add("high", "unknown-package", name, `There is no package called ${name} on npm. Guessed names are a known attack: someone registers the name and waits for an install.`, `Find the real package name in the library's docs. Don't install a guessed name.`);
    } else if (p === null) {
      add("info", "intel-unavailable", name, "Could not reach the npm registry; only offline checks ran.", "Retry with network access before trusting a new package.");
    } else {
      version = resolveSpec(p, range) ?? version; // an exact version npm pulled still gets checked below
      if (!version) add("medium", "unknown-version", name, `No published version of ${name} matches "${range}".`, `Pick a version from \`npm view ${name} versions\`.`);
      else for (const s of signals(p, version)) add(s.severity, s.category, `${name}@${version}`, s.detail, s.fix);
      const downloads = await weeklyDownloads(name);
      if (downloads !== null && downloads < 100) add("medium", "few-downloads", name, `${name} was downloaded ${downloads} time(s) last week.`, "Low use means few eyes on the code; check who publishes it.");
    }
    if (version) {
      const hit = knownBad(name, version);
      if (hit) add("critical", "known-compromise", `${name}@${version}`, `This exact version was published by an attacker (${hit.incident}).`, `Use a different version of ${name}.`, { url: hit.url });
      const vulns = (await osv([{ name, version }]))?.get(`${name}@${version}`) ?? [];
      for (const v of vulns) {
        if (v.malicious) { if (!hit) add("critical", "malicious-package", `${name}@${version}`, `${v.summary} (${v.id}).`, `Do not install ${name}@${version}.`, { url: v.url }); }
        else add(v.severity, "known-vuln", `${name}@${version}`, `${v.summary} (${v.id}).`, v.fixed ? `Use ${name}@${v.fixed} or later.` : "No fixed version is listed; see the advisory.", { url: v.url });
      }
      const key = `${name}@${version}`;
      for (const a of (await socket([{ name, version }]))?.get(key) ?? []) {
        const s = socketFinding(a, key);
        if (s.category === "socket-malware" && findings.some(f => ["known-compromise", "malicious-package"].includes(f.category))) continue;
        add(s.severity, s.category, key, s.detail, s.fix, { url: s.url });
      }
    }
    for (const f of findings) f.types = classify(f.imitates ?? name);
    findings.sort((a, b) => ORDER[a.severity] - ORDER[b.severity]);
    const verdict: Verdict = findings.some(f => BLOCK.has(f.category)) ? "block"
      : findings.some(f => ORDER[f.severity] <= ORDER.medium) ? "ask" : findings.length ? "note" : "ok";
    out.push({ spec, name, version, verdict, findings });
  });
  return out.sort((a, b) => specs.indexOf(a.spec) - specs.indexOf(b.spec));
}
