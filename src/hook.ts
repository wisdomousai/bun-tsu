#!/usr/bin/env bun
// Claude Code hooks. Reads the hook event JSON on stdin, prints the hook's JSON answer on stdout.
//   bun src/hook.ts pre-tool-use    Bash: check packages before bun/npm/pnpm/yarn add or npx/bunx runs them
//   bun src/hook.ts session-start   brief the agent on the project's supply-chain findings
import { existsSync } from "node:fs";
import { basename, join, resolve } from "node:path";

const INSTALLER = /\b(bun|bunx|npm|npx|pnpm|pnpx|yarn)\b/;
const VALUED = new Set(["--registry", "--prefix", "--cwd", "-w", "--workspace", "--filter", "-F", "--tag", "--config", "-c", "--cache", "--userconfig", "--call"]);
const SUB: Record<string, { add: string[]; run: string[] }> = {
  bun: { add: ["add", "a", "install", "i"], run: ["x"] },
  npm: { add: ["install", "i", "in", "add", "isntall"], run: ["exec", "x"] },
  pnpm: { add: ["add", "install", "i"], run: ["dlx", "exec"] },
  yarn: { add: ["add"], run: ["dlx"] },
};

const words = (s: string) => [...s.matchAll(/"([^"]*)"|'([^']*)'|(\S+)/g)].map(m => m[1] ?? m[2] ?? m[3]);

/** Package specs a shell command would install or run from the registry. */
export function installTargets(command: string): string[] {
  const out: string[] = [];
  const plain = command.replace(/\d*(?:>>?|<)(?:&\d+|\s*[^\s&|;<>]+)/g, " "); // drop redirections like 2>&1 and > out.txt
  for (const part of plain.split(/&&|\|\||[;|&\n]/)) {
    const t = words(part.trim());
    while (t.length && (/^\w+=/.test(t[0]) || ["sudo", "command", "exec", "time"].includes(t[0]))) t.shift();
    const tool = basename(t.shift() ?? "");
    let args: string[], runner = false;
    if (["bunx", "npx", "pnpx"].includes(tool)) { args = t; runner = true; }
    else if (SUB[tool]) {
      while (t[0]?.startsWith("-")) if (VALUED.has(t.shift()!)) t.shift(); // global flags before the subcommand
      if (tool === "yarn" && t[0] === "global") t.shift();
      const sub = t.shift() ?? "";
      if (SUB[tool].add.includes(sub)) args = t;
      else if (SUB[tool].run.includes(sub)) { args = t; runner = true; }
      else continue;
    } else continue;
    for (let i = 0; i < args.length; i++) {
      const a = args[i];
      if (a === "-p" || a === "--package") { if (args[i + 1]) out.push(args[++i]); continue; }
      if (a.startsWith("--package=")) { out.push(a.slice(10)); continue; }
      if (VALUED.has(a)) { i++; continue; }
      if (a.startsWith("-") || /[$`(){}*]/.test(a)) continue;
      out.push(a);
      if (runner) break; // the rest are arguments to the binary
    }
  }
  return out;
}

type Answer = Record<string, unknown> | null;

export async function preToolUse(input: any): Promise<Answer> {
  const command = input?.tool_input?.command;
  if (input?.tool_name !== "Bash" || typeof command !== "string" || !INSTALLER.test(command)) return null;
  const specs = installTargets(command);
  if (!specs.length) return null;
  const { check } = await import("./lib/check.ts");
  const { customRegistry } = await import("./lib/scout.ts");
  const results = await check(specs, { customRegistry: customRegistry(resolve(input.cwd ?? ".")) });
  const lines = results.flatMap(r => r.findings.map(f => `- ${r.version ? `${r.name}@${r.version}` : r.name} [${f.severity} ${f.category}]: ${f.detail} Fix: ${f.fix}${f.url ? ` (${f.url})` : ""}`));
  if (!lines.length) return null;
  const worst = results.some(r => r.verdict === "block") ? "block" : results.some(r => r.verdict === "ask") ? "ask" : "note";
  const head = { block: "Bun Tsu blocked this install.", ask: "Bun Tsu wants a human to confirm this install.", note: "Bun Tsu checked the packages in this command." }[worst];
  const body = `${head}\n${lines.join("\n")}`;
  const out = { hookEventName: "PreToolUse", additionalContext: body } as Record<string, string>;
  if (worst !== "note") Object.assign(out, { permissionDecision: worst === "block" ? "deny" : "ask", permissionDecisionReason: body });
  return { hookSpecificOutput: out };
}

export async function sessionStart(input: any): Promise<Answer> {
  const dir = resolve(input?.cwd ?? ".");
  if (!existsSync(join(dir, "package.json"))) return null;
  const { scout } = await import("./lib/scout.ts");
  const { style } = (await import("./lib/config.ts")).resolveStyle(dir);
  const r = await scout(dir, { network: "osv" }).catch(() => null);
  const serious = r?.findings.filter(f => ["critical", "high", "medium"].includes(f.severity)) ?? [];
  if (!r || !serious.length) return null;
  const shown = serious.slice(0, 12);
  const text = [`Bun Tsu supply-chain findings for ${r.project} (${r.declared.total} declared deps, ${r.resolved} resolved versions, ${r.intel}):`,
    ...shown.map(f => `- ${f.severity.toUpperCase()} ${f.subject} [${f.category}]: ${f.detail} Fix: ${f.fix}`),
    serious.length > shown.length ? `(${serious.length - shown.length} more; run \`bunx @wisdomousai/bun-tsu scout --json\`.)` : "",
    "Mention critical and high findings to the user when they touch dependencies. Do not install, remove or upgrade packages to fix these unless the user asks.",
    style === "prophecy" ? "The user chose the Bun Tsu prophecy style: when you report these findings, write the scroll first and then the plain table, as the bun-tsu skill describes." : "",
    style === "claudish" ? "The user chose the Bun Tsu claudish style: when you report these findings, write them as the parody of AI slop the bun-tsu skill describes, keeping every fact and fix exact." : ""].filter(Boolean).join("\n");
  return { hookSpecificOutput: { hookEventName: "SessionStart", additionalContext: text } };
}

export async function runHook(event: string, stdin: string): Promise<Answer> {
  let input: any = {};
  try { input = JSON.parse(stdin || "{}"); } catch { return null; }
  if (event === "pre-tool-use") return preToolUse(input);
  if (event === "session-start") return sessionStart(input);
  throw new Error(`Unknown hook event "${event}". Use pre-tool-use or session-start.`);
}

if (import.meta.main) {
  const answer = await runHook(process.argv[2] ?? "", await Bun.stdin.text());
  if (answer) console.log(JSON.stringify(answer));
}
