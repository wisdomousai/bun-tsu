import { test, expect, beforeAll, afterAll } from "bun:test";
import { mkdtempSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { signals, resolveSpec } from "../src/lib/signals.ts";
import { check, parseSpec } from "../src/lib/check.ts";
import { installTargets, preToolUse } from "../src/hook.ts";
import { scanner } from "../src/scanner.ts";
import { scout } from "../src/lib/scout.ts";

const H = 3_600_000, now = Date.parse("2026-11-11T12:00:00Z");
const at = (hoursAgo: number) => new Date(now - hoursAgo * H).toISOString();
const ver = (v: string, extra: any = {}) => ({ name: "widget", version: v, dist: { tarball: "" }, _npmUser: { name: "alice" }, ...extra });
const widget = {
  name: "widget", "dist-tags": { latest: "2.1.0" },
  time: { created: at(9000), modified: at(5), "1.0.0": at(9000), "2.0.0": at(400), "2.1.0": at(5) },
  versions: {
    "1.0.0": ver("1.0.0"),
    "2.0.0": ver("2.0.0", { dist: { attestations: { url: "x" } } }),
    "2.1.0": ver("2.1.0", { _npmUser: { name: "mallory" }, scripts: { postinstall: "node setup.js" } }),
  },
};

test("signals: a hijacked-looking release", () => {
  const cats = signals(widget, "2.1.0", now).map(s => s.category).sort();
  expect(cats).toEqual(["fresh-release", "install-script-added", "new-publisher", "provenance-dropped"]);
});

test("signals: old major, pulled version", () => {
  expect(signals(widget, "1.0.0", now).map(s => s.category)).toEqual(["outdated"]);
  expect(signals(widget, "1.9.9", now).map(s => s.category)).toEqual(["version-unpublished"]);
  expect(resolveSpec(widget, "^2.0.0")).toBe("2.1.0");
  expect(resolveSpec(widget, "latest")).toBe("2.1.0");
});

test("spec parsing", () => {
  expect(parseSpec("zod@^4")).toEqual({ name: "zod", range: "^4" });
  expect(parseSpec("@types/node")).toEqual({ name: "@types/node", range: "latest" });
  expect(parseSpec("str@npm:string-width@4")).toEqual({ name: "string-width", range: "4" });
  expect(parseSpec("github:user/repo")).toEqual({ remote: "github:user/repo" });
  expect(parseSpec("./local")).toBeUndefined();
});

test("install commands an agent might run", () => {
  expect(installTargets("bun add zod@3 expresss -d 2>&1 | tail -5")).toEqual(["zod@3", "expresss"]);
  expect(installTargets("cd web && npm i -D @types/node > log.txt")).toEqual(["@types/node"]);
  expect(installTargets("npx -y create-vite@latest app --template react")).toEqual(["create-vite@latest"]);
  expect(installTargets("pnpm --filter web add axios")).toEqual(["axios"]);
  expect(installTargets("yarn global add left-pad")).toEqual(["left-pad"]);
  expect(installTargets("bun install")).toEqual([]);
  expect(installTargets("git commit -m 'bun add foo'")).toEqual([]);
});

// a fake registry and OSV
const MAL = { id: "MAL-2026-1", summary: "Malicious code in evil-pkg (npm)", affected: [] };
const routes: Record<string, any> = {
  "registry.npmjs.org/widget": widget,
  "registry.npmjs.org/evil-pkg": { ...widget, name: "evil-pkg", "dist-tags": { latest: "1.0.0" }, versions: { "1.0.0": ver("1.0.0") }, time: { created: at(9000), "1.0.0": at(9000) } },
  "api.osv.dev/v1/vulns/MAL-2026-1": MAL,
};
const realFetch = globalThis.fetch;
beforeAll(() => {
  delete process.env.BUN_TSU_OFFLINE;
  process.env.BUN_TSU_CACHE = mkdtempSync(join(tmpdir(), "bt-cache-"));
  globalThis.fetch = (async (url: string, init?: RequestInit) => {
    const u = String(url).replace(/^https:\/\//, "");
    if (u.endsWith("/querybatch")) {
      const { queries } = JSON.parse(String(init!.body));
      return Response.json({ results: queries.map((q: any) => q.package.name === "evil-pkg" ? { vulns: [{ id: "MAL-2026-1" }] } : {}) });
    }
    if (u.includes("api.npmjs.org/downloads")) return Response.json({ downloads: 50_000 });
    return routes[u] ? Response.json(routes[u]) : new Response("not found", { status: 404 });
  }) as typeof fetch;
});
afterAll(() => { globalThis.fetch = realFetch; });

test("check: malware and guessed names are blocked, a risky release asks", async () => {
  const r = await check(["evil-pkg", "made-up-helper", "widget"]);
  expect(r.map(x => `${x.name}:${x.verdict}`)).toEqual(["evil-pkg:block", "made-up-helper:block", "widget:ask"]);
  expect(r[0].findings[0].category).toBe("malicious-package");
  expect(r[1].findings[0].category).toBe("unknown-package");
});

test("hook: denies a malicious install, stays silent on unrelated commands", async () => {
  const deny: any = await preToolUse({ tool_name: "Bash", tool_input: { command: "bun add evil-pkg" }, cwd: "." });
  expect(deny.hookSpecificOutput.permissionDecision).toBe("deny");
  expect(deny.hookSpecificOutput.permissionDecisionReason).toContain("MAL-2026-1");
  expect(await preToolUse({ tool_name: "Bash", tool_input: { command: "ls -la" } })).toBeNull();
  expect(await preToolUse({ tool_name: "Read", tool_input: { file_path: "package.json" } })).toBeNull();
});

test("scanner: OSV malware is fatal", async () => {
  const out = await scanner.scan({ packages: [{ name: "evil-pkg", version: "1.0.0", requestedRange: "1.0.0", tarball: "" }] } as any);
  expect(out.map(a => `${a.package}:${a.level}`)).toEqual(["evil-pkg:fatal"]);
});

test("scout: OSV malware in the lockfile and an unknown direct dependency", async () => {
  const dir = mkdtempSync(join(tmpdir(), "bt-"));
  writeFileSync(join(dir, "package.json"), JSON.stringify({ name: "p", dependencies: { "evil-pkg": "^1.0.0", "made-up-helper": "^1.0.0" } }));
  writeFileSync(join(dir, "bun.lock"), `{"lockfileVersion":1,"packages":{"evil-pkg":["evil-pkg@1.0.0","",{},"sha512-x"]}}`);
  const r = await scout(dir);
  const cats = r.findings.map(f => `${f.category}:${f.subject}`);
  expect(cats).toContain("malicious-package:evil-pkg@1.0.0");
  expect(cats).toContain("unknown-package:made-up-helper");
});
