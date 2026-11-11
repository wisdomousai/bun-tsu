import { test, expect, beforeAll } from "bun:test";
import { scanner } from "../src/scanner.ts";
import { imitates, classify } from "../src/lib/classify.ts";
import { pick, allQuotes } from "../src/lib/quotes.ts";
import { scout } from "../src/lib/scout.ts";
import { prophesy } from "../src/lib/prophecy.ts";
import { claudify } from "../src/lib/claudish.ts";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { resolveStyle, setStyle } from "../src/lib/config.ts";
import { join } from "node:path";
import { tmpdir } from "node:os";

// these tests use only the built-in data; test/intel.test.ts mocks the network
beforeAll(() => { process.env.BUN_TSU_OFFLINE = "1"; });

const pkg = (name: string, version: string, requestedRange = version) => ({ name, version, requestedRange, tarball: "" });

test("scanner: documented compromised versions are fatal", async () => {
  const out = await scanner.scan({ packages: [pkg("chalk", "5.6.1"), pkg("event-stream", "3.3.6"), pkg("chalk", "5.6.2")] } as any);
  expect(out.map(a => `${a.package}:${a.level}`)).toEqual(["chalk:fatal", "event-stream:fatal"]);
});

test("scanner: clean packages pass", async () => {
  expect(await scanner.scan({ packages: [pkg("react", "18.3.1"), pkg("zod", "3.23.8")] } as any)).toEqual([]);
});

test("typosquat detection, with legit look-alikes allowed", () => {
  expect(imitates("expresss")).toBe("express");
  expect(imitates("colrs")).toBe("colors");
  expect(imitates("lodahs")).toBeUndefined(); // two edits: not flagged
  for (const ok of ["react", "uid", "preact", "chai", "blob"]) expect(imitates(ok)).toBeUndefined();
});

test("classification", () => {
  expect(classify("jsonwebtoken")).toContain("auth");
  expect(classify("@types/node")).toEqual(["types"]);
  expect(classify("uuid")).not.toContain("ui");
  expect(classify("sharp")).toContain("native");
});

test("quote picker never returns empty and honours filters", () => {
  expect(allQuotes().length).toBeGreaterThan(150);
  expect(pick({ vector: "nonsense" }).length).toBe(1);
  expect(pick({ vector: "typosquat" })[0].vectors).toContain("typosquat");
  expect(pick({ type: "database", n: 3 }).every(q => q.types.includes("database"))).toBe(true);
});

test("scout + prophecy on a doomed fixture; secrets never echoed", async () => {
  const dir = mkdtempSync(join(tmpdir(), "bt-"));
  writeFileSync(join(dir, "package.json"), JSON.stringify({ name: "doomed", dependencies: { expresss: "*", "jsonwebtoken": "^9.0.0" } }));
  writeFileSync(join(dir, ".npmrc"), "//registry.npmjs.org/:_authToken=npm_SUPERSECRET\n");
  writeFileSync(join(dir, "bun.lock"), `{"lockfileVersion":1,"packages":{"debug":["debug@4.4.2","",{},"sha512-x"],}}`);
  const r = await scout(dir);
  const cats = r.findings.map(f => f.category);
  expect(cats).toContain("known-compromise");
  expect(cats).toContain("typosquat-suspect");
  expect(cats).toContain("committed-token");
  expect(JSON.stringify(r)).not.toContain("SUPERSECRET");
  const p = prophesy(r);
  expect(p.serene).toBe(false);
  expect(p.verses[0].finding.severity).toBe("critical");
});

test("a clean project gets a serene prophecy", async () => {
  const dir = mkdtempSync(join(tmpdir(), "bt-"));
  writeFileSync(join(dir, "package.json"), JSON.stringify({ name: "zen", dependencies: { zod: "3.23.8" } }));
  writeFileSync(join(dir, "bun.lock"), `{"lockfileVersion":1,"packages":{}}`);
  expect(prophesy(await scout(dir)).serene).toBe(true);
});

test("style: flag, then env, then repo, then global, then plain", () => {
  const dir = mkdtempSync(join(tmpdir(), "bt-")), xdg = mkdtempSync(join(tmpdir(), "bt-xdg-"));
  const saved = { xdg: process.env.XDG_CONFIG_HOME, style: process.env.BUN_TSU_STYLE };
  process.env.XDG_CONFIG_HOME = xdg; delete process.env.BUN_TSU_STYLE;
  try {
    writeFileSync(join(dir, "package.json"), JSON.stringify({ name: "s" }, null, 4));
    expect(resolveStyle(dir)).toEqual({ style: "plain", source: "default" });
    setStyle("prophecy", { global: true });
    expect(resolveStyle(dir)).toEqual({ style: "prophecy", source: "global" });
    setStyle("plain", { dir });
    expect(resolveStyle(dir)).toEqual({ style: "plain", source: "repo" });
    expect(readFileSync(join(dir, "package.json"), "utf8")).toContain('    "bun-tsu"'); // keeps the file's indent
    process.env.BUN_TSU_STYLE = "prophecy";
    expect(resolveStyle(dir)).toEqual({ style: "prophecy", source: "env" });
    expect(resolveStyle(dir, "plain")).toEqual({ style: "plain", source: "flag" });
  } finally {
    if (saved.xdg === undefined) delete process.env.XDG_CONFIG_HOME; else process.env.XDG_CONFIG_HOME = saved.xdg;
    if (saved.style === undefined) delete process.env.BUN_TSU_STYLE; else process.env.BUN_TSU_STYLE = saved.style;
  }
});

test("scanner: plain instructions by default, an omen in the prophecy style", async () => {
  const scan = async () => (await scanner.scan({ packages: [pkg("chalk", "5.6.1")] } as any))[0].description;
  expect(await scan()).toBe("Bun Tsu: chalk@5.6.1 was published by an attacker (chalk, debug and friends (Sept 2025)). Do not install it; use another version.");
  process.env.BUN_TSU_STYLE = "prophecy";
  try { expect(await scan()).toStartWith('Bun Tsu: "The one who came as chalk@5.6.1 wears stolen armour."'); }
  finally { delete process.env.BUN_TSU_STYLE; }
});

test("claudish: real findings and fixes inside the slop", async () => {
  const dir = mkdtempSync(join(tmpdir(), "bt-"));
  writeFileSync(join(dir, "package.json"), JSON.stringify({ name: "sloppy", dependencies: { expresss: "1.0.0" } }));
  writeFileSync(join(dir, "bun.lock"), `{"lockfileVersion":1,"packages":{"debug":["debug@4.4.2","",{},"sha512-x"],}}`);
  const r = await scout(dir);
  const text = claudify(r);
  expect(text).toContain("This isn't just");
  expect(text).toContain("One critical issue.");
  for (const f of r.findings.filter(f => f.severity !== "info")) { expect(text).toContain(f.detail); expect(text).toContain(f.fix); }
  writeFileSync(join(dir, "bun.lock"), `{"lockfileVersion":1,"packages":{}}`);
  writeFileSync(join(dir, "package.json"), JSON.stringify({ name: "zen", dependencies: { zod: "3.23.8" } }));
  expect(claudify(await scout(dir))).toContain("One package. Zero findings.");
});
