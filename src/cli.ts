#!/usr/bin/env bun
// bun-tsu: the CLI.
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { scout, customRegistry, type Report, type Severity } from "./lib/scout.ts";
import { resolveStyle, setStyle, globalConfigPath, STYLES, type Style } from "./lib/config.ts";
import { check } from "./lib/check.ts";
import { runHook } from "./hook.ts";
import { prophesy, numeral, dominantType } from "./lib/prophecy.ts";
import { claudify } from "./lib/claudish.ts";
import { pick, allQuotes, VECTORS, TYPES } from "./lib/quotes.ts";
import { banner, scroll, mini, c, wrap, seal } from "./lib/art.ts";

const argv = process.argv.slice(2);
const flag = (k: string) => argv.includes(`--${k}`);
const opt = (k: string) => { const i = argv.indexOf(`--${k}`); return i >= 0 ? argv[i + 1] : undefined; };
const valued = new Set(["vector", "type", "source", "n"].map(k => `--${k}`));
const positional = argv.filter((a, i) => !a.startsWith("--") && !valued.has(argv[i - 1] ?? ""));
const commands = ["report", "prophecy", "quote", "scout", "check", "hook", "tags", "init", "config", "help"];
const cmd = commands.includes(positional[0]) ? positional.shift()! : "report";
const flagged: Style | undefined = cmd === "prophecy" || flag("prophecy") ? "prophecy" : flag("claudish") ? "claudish" : flag("plain") ? "plain" : undefined;
const { style, source } = resolveStyle(cmd === "report" || cmd === "prophecy" ? positional[0] ?? "." : ".", flagged);
const art = style === "prophecy" && !flag("no-art") && !flag("json");
const SEV = { critical: c.red, high: c.seal, medium: c.yellow, low: c.cyan, info: c.grey } as const;

function help() {
  console.log(`${art ? banner() : ""}
  ${c.bold("Usage")}
    bun-tsu [dir]                       Check the project; list problems and what to do
    bun-tsu prophecy [dir]              The same, delivered as Bun Tsu's scroll first
    bun-tsu quote [--vector V] [--type T] [--source classic|apocrypha] [--n N]
    bun-tsu scout [dir] --json          Raw findings, for agents and CI
    bun-tsu check <pkg[@range]>...      Vet packages before installing them
    bun-tsu hook <event>                Claude Code hook (pre-tool-use, session-start), JSON on stdin
    bun-tsu tags                        List attack vectors and package types
    bun-tsu config [style <plain|prophecy|claudish>] [--global]
                                        Show or set the output style for this repo (package.json) or everywhere
    bun-tsu init [--preload] [--claude] Install Bun Tsu as your bun install security scanner
                                        (--claude also adds the Claude Code hooks to .claude/settings.json)

    Without installing: bunx @wisdomousai/bun-tsu [command]

  ${c.bold("Flags")}
    --audit     also consult \`bun audit\` for known advisories
    --offline   skip OSV and the npm registry (also BUN_TSU_OFFLINE=1)
    --strict    exit 1 if anything critical or high is found
    --all       include info findings in the report
    --prophecy  use the prophecy style; --claudish the AI-slop one; --plain forces plain (also BUN_TSU_STYLE)
    --no-art    skip the ASCII art in the prophecy style (NO_COLOR also respected)
    --json      machine-readable output
`);
}

function showQuote() {
  const qs = pick({ vector: opt("vector"), type: opt("type"), source: opt("source") as any, n: Number(opt("n") ?? 1) });
  if (flag("json")) return console.log(JSON.stringify(qs.length === 1 ? qs[0] : qs, null, 2));
  if (art) console.log(banner("The Oracle"));
  for (const q of qs) {
    for (const l of wrap(`\u201C${q.q}\u201D`, 64)) console.log("    " + c.italic(l));
    console.log("      " + c.grey("\u2014 " + q.src) + "\n");
  }
}

function tags() {
  const all = allQuotes();
  const count = (k: "vectors" | "types", n: string) => all.filter(q => q[k].includes(n)).length;
  if (flag("json")) return console.log(JSON.stringify({ total: all.length, vectors: VECTORS, types: TYPES }, null, 2));
  console.log(`\n  ${c.bold(`${all.length} sayings on the scroll`)}\n\n  ${c.bold("Attack vectors")}`);
  for (const [k, d] of Object.entries(VECTORS)) console.log(`    ${c.bun(k.padEnd(22))}${String(count("vectors", k)).padStart(3)}  ${c.grey(d)}`);
  console.log(`\n  ${c.bold("Package types")}`);
  for (const [k, d] of Object.entries(TYPES)) console.log(`    ${c.bun(k.padEnd(22))}${String(count("types", k)).padStart(3)}  ${c.grey(d)}`);
  console.log();
}

function init() {
  const path = join(process.cwd(), "bunfig.toml");
  let text = existsSync(path) ? readFileSync(path, "utf8") : "";
  const changes: string[] = [];
  if (/^\s*scanner\s*=/m.test(text)) changes.push("a security scanner is already configured; left it alone");
  else { text += `${text && !text.endsWith("\n") ? "\n" : ""}\n[install.security]\nscanner = "@wisdomousai/bun-tsu"\n`; changes.push("set bun-tsu as the install security scanner"); }
  if (flag("preload")) {
    if (/^\s*preload\s*=/m.test(text)) changes.push("a preload is already configured; add \"@wisdomousai/bun-tsu/preload\" to it by hand");
    else { text = `preload = ["@wisdomousai/bun-tsu/preload"]\n` + text; changes.push("added the daily-quote preload"); }
  }
  writeFileSync(path, text);
  if (flag("claude")) changes.push(claudeHooks());
  console.log(art ? mini("The scanner is posted at the gate.") : "\n  Bun Tsu is now the install security scanner.");
  for (const ch of changes) console.log("  " + c.green("\u2713 ") + ch);
  console.log(`\n  Make sure it is installed: ${c.bold("bun add -d @wisdomousai/bun-tsu")}\n  Then every ${c.bold("bun install")} passes before Bun Tsu.\n`);
}

function claudeHooks(): string {
  const dir = join(process.cwd(), ".claude"), path = join(dir, "settings.json");
  let settings: any = {};
  try { settings = existsSync(path) ? JSON.parse(readFileSync(path, "utf8")) : {}; } catch { return ".claude/settings.json is not valid JSON; left it alone"; }
  const cmd = (event: string) => `bunx @wisdomousai/bun-tsu hook ${event}`;
  const want: [string, string | undefined, string, number][] = [["PreToolUse", "Bash", "pre-tool-use", 30], ["SessionStart", "startup|clear|compact", "session-start", 30]];
  settings.hooks ??= {};
  let added = 0;
  for (const [event, matcher, name, timeout] of want) {
    const list = (settings.hooks[event] ??= []);
    if (JSON.stringify(list).includes(cmd(name))) continue;
    list.push({ ...(matcher ? { matcher } : {}), hooks: [{ type: "command", command: cmd(name), timeout }] }); added++;
  }
  mkdirSync(dir, { recursive: true });
  writeFileSync(path, JSON.stringify(settings, null, 2) + "\n");
  return added ? "added the Claude Code hooks to .claude/settings.json" : "the Claude Code hooks were already in .claude/settings.json";
}

async function checkPackages() {
  const specs = positional;
  if (!specs.length) { console.error(c.red("  Name at least one package: bun-tsu check zod@^4 left-pad")); process.exit(2); }
  const results = await check(specs, { customRegistry: customRegistry(process.cwd()) });
  const blocked = results.some(r => r.verdict === "block");
  if (flag("json")) { console.log(JSON.stringify(results, null, 2)); process.exit(blocked ? 1 : 0); }
  const V = { block: c.red("BLOCK"), ask: c.seal("ASK  "), note: c.yellow("NOTE "), ok: c.green("OK   ") };
  console.log();
  for (const r of results) {
    console.log(`  ${V[r.verdict]} ${c.bold(r.version ? `${r.name}@${r.version}` : r.name)}`);
    for (const f of r.findings) {
      console.log(`        ${SEV[f.severity](f.severity.padEnd(9))}${c.grey(f.category)}`);
      for (const l of wrap(f.detail, 66)) console.log("          " + l);
      for (const l of wrap("\u2192 " + f.fix, 66)) console.log("          " + c.green(l));
      if (f.url) console.log("          " + c.grey(f.url));
    }
  }
  console.log();
  process.exit(blocked ? 1 : 0);
}

function config() {
  if (positional[0] === "style") {
    const want = positional[1] as Style;
    if (!STYLES.includes(want)) { console.error(c.red(`  Style must be one of: ${STYLES.join(", ")}`)); process.exit(2); }
    try { console.log(`  Style set to ${c.bold(want)} in ${setStyle(want, { global: flag("global") })}`); }
    catch (e: any) { console.error(c.red("  " + e.message)); process.exit(2); }
    return;
  }
  console.log(`  style: ${c.bold(style)} (${source})\n  repo setting: package.json "bun-tsu": { "style": "..." }\n  global setting: ${globalConfigPath()}`);
}

const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "info"];

function plain(report: Report) {
  const shown = report.findings.filter(f => flag("all") || f.severity !== "info");
  const n = (s: Severity) => report.findings.filter(f => f.severity === s).length;
  console.log(`\n  ${c.bold(`Bun Tsu report for ${report.project}`)}`);
  console.log(`  Checked ${report.declared.total} declared dependencies and ${report.resolved} resolved versions (${report.intel}).`);
  if (!shown.length) console.log("  No problems found.\n");
  else console.log(`  Found ${SEVERITIES.filter(n).map(s => `${n(s)} ${s}`).join(", ")}. Most severe first; each item says what to do.\n`);
  const groups = new Map<string, typeof shown>();
  for (const f of shown) (groups.get(f.subject) ?? groups.set(f.subject, []).get(f.subject)!).push(f);
  [...groups.values()].forEach((fs, i) => {
    console.log(`  ${c.bold(`${i + 1}.`)} ${SEV[fs[0].severity](fs[0].severity.toUpperCase())} ${c.bold(fs[0].subject)}`);
    for (const f of fs) {
      for (const l of wrap(`Problem (${f.category}): ${f.detail}`, 70)) console.log("     " + l);
      for (const l of wrap(`Action: ${f.fix}`, 70)) console.log("     " + c.green(l));
      if (f.url) console.log("     " + c.grey(`See: ${f.url}`));
    }
    console.log();
  });
  const hidden = report.findings.length - shown.length;
  if (hidden) console.log(c.grey(`  ${hidden} info finding(s) not shown; add --all to include them.\n`));
}

async function report() {
  const dir = positional[0] ?? ".";
  let report;
  try { report = await scout(dir, { audit: flag("audit"), network: flag("offline") ? "none" : "full" }); }
  catch (e: any) { console.error(c.red("  " + e.message)); process.exit(2); }
  const strictFail = flag("strict") && report.findings.some(f => f.severity === "critical" || f.severity === "high");
  if (flag("json") || cmd === "scout") console.log(JSON.stringify({ ...report, style }, null, 2));
  else if (style === "prophecy") prophecy(report);
  else if (style === "claudish") console.log("\n" + claudify(report) + "\n");
  else plain(report);
  process.exit(strictFail ? 1 : 0);
}

function prophecy(report: Report) {
  const p = prophesy(report);
  if (art) console.log(banner());
  const paras = [c.italic(p.opening), ...p.verses.map((v, i) => `${c.bold(numeral(i) + ".")} ${v.omen}`),
    c.italic(`\u201C${p.closing.q}\u201D`) + " " + c.grey("\u2014 " + p.closing.src.split(",")[0])];
  console.log(scroll(p.title, paras));

  console.log(`\n  ${c.bold("The plain scroll")}  ${c.grey(`(${report.declared.total} declared, ${report.resolved} resolved, ${report.intel}, profile: ${dominantType(report)})`)}\n`);
  if (p.serene) console.log("  Nothing alarming. " + (report.findings[0] ? report.findings[0].fix : "Carry on."));
  p.verses.forEach((v, i) => {
    const f = v.finding;
    console.log(`  ${c.bold(numeral(i).padEnd(4))}${SEV[f.severity](f.severity.toUpperCase().padEnd(9))}${c.bold(f.subject)}  ${c.grey(f.vector)}`);
    for (const g of [f, ...v.also]) {
      for (const l of wrap(g.detail, 66)) console.log("              " + l);
      for (const l of wrap("\u2192 " + g.fix, 66)) console.log("              " + c.green(l));
      if (g.url) console.log("              " + c.grey(g.url));
    }
    console.log();
  });
  const rest = report.findings.filter(f => f.severity !== "info").length - p.verses.reduce((n, v) => n + 1 + v.also.length, 0);
  if (rest > 0) console.log(c.grey(`  ${rest} lesser omen(s) not shown. Run \`bun-tsu scout --json\` for all of them.\n`));
  if (art) console.log(seal().split("\n").map(l => "  " + l).join("\n") + "\n");
}

if (cmd === "help" || flag("help")) help();
else if (cmd === "quote") showQuote();
else if (cmd === "tags") tags();
else if (cmd === "init") init();
else if (cmd === "config") config();
else if (cmd === "check") await checkPackages();
else if (cmd === "hook") { const a = await runHook(positional[0] ?? "", await Bun.stdin.text()); if (a) console.log(JSON.stringify(a)); }
else await report();
