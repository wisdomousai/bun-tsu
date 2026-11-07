import { test, expect } from "bun:test";
import { scanner } from "../src/scanner.ts";
import { imitates, classify } from "../src/lib/classify.ts";
import { pick, allQuotes } from "../src/lib/quotes.ts";
import { scout } from "../src/lib/scout.ts";
import { prophesy } from "../src/lib/prophecy.ts";
import { mkdtempSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";

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
