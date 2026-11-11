// Registry signals for one package version. Pure functions over a packument, so they test without a network.
import type { Severity } from "./scout.ts";

export type Signal = { severity: Severity; category: string; detail: string; fix: string };
const HOOKS = ["preinstall", "install", "postinstall"];
const DAY = 86_400_000;
export const FRESH_HOURS = Number(process.env.BUN_TSU_FRESH_HOURS ?? 72);

const isPre = (v: string) => v.includes("-");
const proven = (m: any) => !!(m?.dist?.attestations || m?._npmUser?.trustedPublisher);
const hooksOf = (m: any) => HOOKS.filter(h => m?.scripts?.[h]);
// release line: the major, or 0.minor before 1.0
const line = (v: string) => { const [a, b] = v.split("."); return a === "0" ? `0.${b}` : a; };
const ago = (h: number) => h < 1 ? "less than an hour" : h < 48 ? `${Math.round(h)} hours` : `${Math.round(h / 24)} days`;

/** Highest published version matching a dist-tag, exact version or range. */
export function resolveSpec(p: any, spec = "latest"): string | undefined {
  const s = spec.trim() || "latest";
  if (p?.["dist-tags"]?.[s]) return p["dist-tags"][s];
  if (p?.versions?.[s]) return s;
  const ok = (v: string) => { try { return Bun.semver.satisfies(v, s); } catch { return false; } };
  return Object.keys(p?.versions ?? {}).filter(ok).sort(Bun.semver.order).pop();
}

export function signals(p: any, version: string, now = Date.now()): Signal[] {
  const out: Signal[] = [];
  const add = (severity: Severity, category: string, detail: string, fix: string) => out.push({ severity, category, detail, fix });
  const name = p.name, m = p.versions?.[version], time = p.time ?? {};
  if (!m) {
    add("high", "version-unpublished", `npm no longer serves ${name}@${version}. Versions are usually pulled for malware or a broken release.`, `Move to a version npm still publishes and find out why ${version} was removed.`);
    return out;
  }
  const published = Date.parse(time[version]);
  const hours = (now - published) / 3_600_000;
  if (hours < FRESH_HOURS) add("medium", "fresh-release", `${name}@${version} was published ${ago(hours)} ago. Hijacked releases are usually caught and pulled within days.`, `Prefer the previous release until this one is ${FRESH_HOURS} hours old, or read its diff first.`);
  const days = (now - Date.parse(time.created)) / DAY;
  if (days < 30) add("medium", "young-package", `${name} first appeared on npm ${ago(days * 24)} ago.`, `Check the repository, maintainers and downloads before trusting ${name}.`);

  // compare with the release published just before this one
  const earlier = Object.keys(p.versions).filter(v => v !== version && (isPre(version) || !isPre(v)) && Date.parse(time[v]) < published)
    .sort((a, b) => Date.parse(time[a]) - Date.parse(time[b]));
  const prevV = earlier.at(-1), prev = prevV && p.versions[prevV];
  if (prev) {
    if (proven(prev) && !proven(m)) add("high", "provenance-dropped", `${prevV} was published with provenance or trusted publishing; ${version} was not. Stolen tokens publish without it.`, `Stay on ${name}@${prevV} until the maintainers confirm ${version}.`);
    if (!hooksOf(prev).length && hooksOf(m).length) add("high", "install-script-added", `${version} adds a ${hooksOf(m).join("/")} script that ${prevV} did not have.`, `Read the script before installing; stay on ${prevV} if the release notes don't explain it.`);
    const who = m._npmUser?.name, before = new Set(earlier.map(v => p.versions[v]?._npmUser?.name).filter(Boolean));
    if (who && before.size && !before.has(who)) add("medium", "new-publisher", `${version} was published by "${who}", who never published an earlier version of ${name}.`, `Confirm ${who} is a real maintainer (repository, release notes) before upgrading.`);
  }

  if (m.deprecated) add("medium", "deprecated", `Marked deprecated: ${String(m.deprecated).slice(0, 100)}`, `Find the maintained successor to ${name}.`);
  const latest = p["dist-tags"]?.latest;
  if (latest && !isPre(version) && line(latest) !== line(version) && Bun.semver.order(latest, version) > 0)
    add("low", "outdated", `Resolved ${version}; latest is ${latest}. Old major versions stop getting security fixes.`, `Plan an upgrade to ${name}@${latest}.`);
  const years = (now - Date.parse(time[latest] ?? time.modified)) / DAY / 365;
  if (!m.deprecated && years > 2) add("low", "unmaintained", `No release of ${name} in ${Math.floor(years)} years. Abandoned packages are a target for account takeover.`, `Look for a maintained alternative, or vendor it.`);
  return out;
}
