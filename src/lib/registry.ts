// Network intel: the npm registry, npm download counts, OSV.dev (malware + advisories) and
// Socket's free firewall API (malware found by analysing package contents).
// Disk-cached, short timeouts. Every call returns null on a bad network instead of throwing.
import { createHash } from "node:crypto";
import { mkdirSync, readFileSync, writeFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { homedir } from "node:os";
import type { Severity } from "./scout.ts";
import { version as VERSION } from "../../package.json";

const REGISTRY = (process.env.BUN_TSU_REGISTRY ?? "https://registry.npmjs.org").replace(/\/$/, "");
const OSV = "https://api.osv.dev/v1";
const cacheDir = () => process.env.BUN_TSU_CACHE ?? join(process.env.XDG_CACHE_HOME ?? join(homedir(), ".cache"), "bun-tsu");
export const offline = () => !!process.env.BUN_TSU_OFFLINE;
export const socketEnabled = () => !offline() && !/^(0|false|off)$/i.test(process.env.BUN_TSU_SOCKET ?? "");

type Got = { status: number; json: any };
async function getJSON(url: string, opts: { body?: unknown; ttl?: number; timeout?: number; ndjson?: boolean } = {}): Promise<Got | null> {
  if (offline()) return null;
  const { body, ttl = 3600, timeout = 8000, ndjson } = opts;
  const file = join(cacheDir(), createHash("sha1").update(url + (body ? JSON.stringify(body) : "")).digest("hex") + ".json");
  try { if ((Date.now() - statSync(file).mtimeMs) / 1000 < ttl) return JSON.parse(readFileSync(file, "utf8")); } catch {}
  try {
    const res = await fetch(url, body
      ? { method: "POST", body: JSON.stringify(body), headers: { "content-type": "application/json" }, signal: AbortSignal.timeout(timeout) }
      : { headers: { accept: "application/json", "user-agent": `bun-tsu/${VERSION}` }, signal: AbortSignal.timeout(timeout) });
    if (res.status !== 200 && res.status !== 404) return null;
    const ok = res.status === 200, text = ok ? await res.text() : "";
    const got = { status: res.status, json: !ok ? null : ndjson ? text.split(/\r?\n/).filter(Boolean).map(l => JSON.parse(l)) : JSON.parse(text) };
    try { mkdirSync(cacheDir(), { recursive: true }); writeFileSync(file, JSON.stringify(got)); } catch {}
    return got;
  } catch { return null; }
}

/** Run fn over items, at most n at a time. */
export async function pool<T>(items: T[], n: number, fn: (x: T) => Promise<void>) {
  const queue = [...items];
  await Promise.all(Array.from({ length: Math.min(n, queue.length) }, async () => { while (queue.length) await fn(queue.shift()!); }));
}

const enc = (name: string) => name.startsWith("@") ? "@" + encodeURIComponent(name.slice(1)) : encodeURIComponent(name);

/** Full packument; "missing" when the registry has no such package, null when unreachable. */
export async function packument(name: string): Promise<any | "missing" | null> {
  const r = await getJSON(`${REGISTRY}/${enc(name)}`);
  return r ? (r.status === 404 ? "missing" : r.json) : null;
}

export async function weeklyDownloads(name: string): Promise<number | null> {
  const r = await getJSON(`https://api.npmjs.org/downloads/point/last-week/${name}`, { ttl: 86400 });
  return r?.status === 200 && typeof r.json?.downloads === "number" ? r.json.downloads : r?.status === 404 ? 0 : null;
}

export type Vuln = { id: string; summary: string; severity: Severity; malicious: boolean; fixed?: string; url: string };
const GHSA_SEV: Record<string, Severity> = { CRITICAL: "critical", HIGH: "high", MODERATE: "medium", LOW: "low" };

function toVuln(id: string, d: any, name: string, version: string): Vuln {
  const malicious = id.startsWith("MAL-") || !!d?.database_specific?.cwe_ids?.includes("CWE-506");
  const fixes: string[] = [];
  for (const a of d?.affected ?? []) if (a.package?.ecosystem === "npm" && a.package?.name === name)
    for (const r of a.ranges ?? []) for (const e of r.events ?? []) if (e.fixed) fixes.push(e.fixed);
  const fixed = fixes.filter(f => { try { return Bun.semver.order(f, version) > 0; } catch { return false; } }).sort(Bun.semver.order)[0];
  return { id, summary: d?.summary?.trim() || (malicious ? "Malicious code" : "Known advisory"), malicious,
    severity: malicious ? "critical" : GHSA_SEV[d?.database_specific?.severity] ?? "medium", fixed, url: `https://osv.dev/vulnerability/${id}` };
}

/** OSV lookup for exact versions. Map key is name@version; null when OSV is unreachable. */
export async function osv(pkgs: { name: string; version: string }[]): Promise<Map<string, Vuln[]> | null> {
  const ids = new Map<string, string[]>();
  for (let i = 0; i < pkgs.length; i += 1000) {
    const chunk = pkgs.slice(i, i + 1000);
    const r = await getJSON(`${OSV}/querybatch`, { body: { queries: chunk.map(p => ({ package: { name: p.name, ecosystem: "npm" }, version: p.version })) }, timeout: 15000 });
    if (r?.status !== 200) return null;
    (r.json?.results ?? []).forEach((res: any, j: number) => { if (res?.vulns?.length) ids.set(`${chunk[j].name}@${chunk[j].version}`, res.vulns.map((v: any) => v.id)); });
  }
  const details = new Map<string, any>();
  await pool([...new Set([...ids.values()].flat())], 8, async id => { const r = await getJSON(`${OSV}/vulns/${id}`, { ttl: 86400 }); if (r?.status === 200) details.set(id, r.json); });
  const out = new Map<string, Vuln[]>();
  for (const [key, list] of ids) {
    const at = key.lastIndexOf("@"), name = key.slice(0, at), version = key.slice(at + 1);
    // malware first, then drop records that are aliases of one already kept
    const vulns = list.map(id => toVuln(id, details.get(id), name, version)).sort((a, b) => +b.malicious - +a.malicious);
    const seen = new Set<string>(); const kept: Vuln[] = [];
    for (const v of vulns) { if (seen.has(v.id)) continue; kept.push(v); seen.add(v.id); for (const a of details.get(v.id)?.aliases ?? []) seen.add(a); }
    out.set(key, kept);
  }
  return out;
}

// whole sentences up to about 300 characters
const clip = (t: string) => { t = t.replace(/\s+/g, " ").trim(); return t.length <= 300 ? t : t.slice(0, 300).replace(/(?<=\.)[^.]*$/, "") || t.slice(0, 297) + "..."; };

export type SocketAlert = { type: string; severity: Severity; block: boolean; note: string; fix?: string; alternate?: string; url: string };
const SOCKET_SEV: Record<string, Severity> = { critical: "critical", high: "high", middle: "medium", medium: "medium", low: "low" };

/** Socket's free firewall API, one request per exact version. Keeps alerts Socket's default policy blocks or warns on.
 *  Map key is name@version; null when Socket is disabled (BUN_TSU_SOCKET=0) or unreachable. */
export async function socket(pkgs: { name: string; version: string }[]): Promise<Map<string, SocketAlert[]> | null> {
  if (!socketEnabled() || !pkgs.length) return socketEnabled() ? new Map() : null;
  const out = new Map<string, SocketAlert[]>(); let failed = 0;
  await pool(pkgs, 16, async ({ name, version }) => {
    const r = await getJSON(`https://firewall-api.socket.dev/purl/${encodeURIComponent(`pkg:npm/${name}@${version}`)}`, { ndjson: true, timeout: 10000 });
    if (r?.status !== 200) { failed++; return; }
    const alerts: SocketAlert[] = [];
    for (const a of (r.json as any[]).flatMap(x => x?.alerts ?? [])) if (a.action === "error" || a.action === "warn")
      alerts.push({ type: a.type, severity: SOCKET_SEV[a.severity] ?? "medium", block: a.action === "error",
        note: clip(String(a.props?.note ?? a.props?.description ?? a.type)), fix: a.fix?.description,
        alternate: a.props?.alternatePackage, url: `https://socket.dev/npm/package/${name}/overview/${version}` });
    if (alerts.length) out.set(`${name}@${version}`, alerts);
  });
  return failed === pkgs.length ? null : out;
}

/** Category, detail and fix for a Socket alert, shared by the scout, the check and the install scanner. */
export function socketFinding(a: SocketAlert, key: string) {
  const category = a.type === "malware" ? "socket-malware" : a.block ? "socket-block" : "socket-warning";
  const detail = a.type === "didYouMean" && a.alternate ? `Socket flags ${key} as a possible typosquat of ${a.alternate}.` : `Socket flags ${key} (${a.type}): ${a.note}`;
  return { category, severity: (a.type === "malware" ? "critical" : a.severity) as Severity, detail, fix: a.fix ?? "Review the alert before installing.", url: a.url };
}
