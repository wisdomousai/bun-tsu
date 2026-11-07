#!/usr/bin/env bun
// bun-tsu: the CLI.
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { scout } from "./lib/scout.ts";
import { prophesy, numeral, dominantType } from "./lib/prophecy.ts";
import { pick, allQuotes, VECTORS, TYPES } from "./lib/quotes.ts";
import { banner, scroll, mini, c, wrap, seal } from "./lib/art.ts";

const argv = process.argv.slice(2);
const flag = (k: string) => argv.includes(`--${k}`);
const opt = (k: string) => { const i = argv.indexOf(`--${k}`); return i >= 0 ? argv[i + 1] : undefined; };
const valued = new Set(["vector", "type", "source", "n"].map(k => `--${k}`));
const positional = argv.filter((a, i) => !a.startsWith("--") && !valued.has(argv[i - 1] ?? ""));
const commands = ["prophecy", "quote", "scout", "tags", "init", "help"];
const cmd = commands.includes(positional[0]) ? positional.shift()! : "prophecy";
const art = !flag("no-art") && !flag("json");
const SEV = { critical: c.red, high: c.seal, medium: c.yellow, low: c.cyan, info: c.grey } as const;

function help() {
  console.log(`${art ? banner() : ""}
  ${c.bold("Usage")}
    bun-tsu [dir]                       Read the project and deliver the prophecy
    bun-tsu quote [--vector V] [--type T] [--source classic|apocrypha] [--n N]
    bun-tsu scout [dir] --json          Raw findings, for agents and CI
    bun-tsu tags                        List attack vectors and package types
    bun-tsu init [--preload]            Install Bun Tsu as your bun install security scanner

    Without installing: bunx @wisdomousai/bun-tsu [command]

  ${c.bold("Flags")}
    --audit     also consult \`bun audit\` for known advisories
    --strict    exit 1 if anything critical or high is found
    --no-art    skip the ASCII art (NO_COLOR also respected)
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
  console.log(art ? mini("The scanner is posted at the gate.") : "");
  for (const ch of changes) console.log("  " + c.green("\u2713 ") + ch);
  console.log(`\n  Make sure it is installed: ${c.bold("bun add -d @wisdomousai/bun-tsu")}\n  Then every ${c.bold("bun install")} passes before Bun Tsu.\n`);
}

async function prophecy(json: boolean) {
  const dir = positional[0] ?? ".";
  let report;
  try { report = await scout(dir, { audit: flag("audit") }); }
  catch (e: any) { console.error(c.red("  " + e.message)); process.exit(2); }
  const strictFail = flag("strict") && report.findings.some(f => f.severity === "critical" || f.severity === "high");

  if (json || cmd === "scout") { console.log(JSON.stringify(report, null, 2)); process.exit(strictFail ? 1 : 0); }

  const p = prophesy(report);
  if (art) console.log(banner());
  const paras = [c.italic(p.opening), ...p.verses.map((v, i) => `${c.bold(numeral(i) + ".")} ${v.omen}`),
    c.italic(`\u201C${p.closing.q}\u201D`) + " " + c.grey("\u2014 " + p.closing.src.split(",")[0])];
  console.log(scroll(p.title, paras));

  console.log(`\n  ${c.bold("The plain scroll")}  ${c.grey(`(${report.declared.total} declared, ${report.resolved} resolved, profile: ${dominantType(report)})`)}\n`);
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
  process.exit(strictFail ? 1 : 0);
}

if (cmd === "help" || flag("help")) help();
else if (cmd === "quote") showQuote();
else if (cmd === "tags") tags();
else if (cmd === "init") init();
else await prophecy(flag("json"));
