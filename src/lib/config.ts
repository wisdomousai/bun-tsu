// Output style. "plain" (default): findings and what to do. "prophecy": the scroll, then the plain findings.
// "claudish": the findings as a parody of AI slop.
// Precedence: --prophecy/--claudish/--plain flag, BUN_TSU_STYLE, the repo's package.json "bun-tsu" key, the global config file.
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { homedir } from "node:os";

export type Style = "plain" | "prophecy" | "claudish";
export type StyleSource = "flag" | "env" | "repo" | "global" | "default";
export const STYLES: Style[] = ["plain", "prophecy", "claudish"];

export const globalConfigPath = () => join(process.env.XDG_CONFIG_HOME ?? join(homedir(), ".config"), "bun-tsu", "config.json");
const read = (p: string) => { try { return JSON.parse(readFileSync(p, "utf8")); } catch { return null; } };
const valid = (s: unknown): s is Style => STYLES.includes(s as Style);

export function resolveStyle(dir = process.cwd(), flagged?: Style): { style: Style; source: StyleSource } {
  if (flagged) return { style: flagged, source: "flag" };
  if (valid(process.env.BUN_TSU_STYLE)) return { style: process.env.BUN_TSU_STYLE, source: "env" };
  const repo = read(join(dir, "package.json"))?.["bun-tsu"]?.style;
  if (valid(repo)) return { style: repo, source: "repo" };
  const global = read(globalConfigPath())?.style;
  if (valid(global)) return { style: global, source: "global" };
  return { style: "plain", source: "default" };
}

/** Writes the style to the repo's package.json ("bun-tsu": { "style": ... }) or to the global config file. */
export function setStyle(style: Style, where: { global?: boolean; dir?: string } = {}): string {
  if (where.global) {
    const path = globalConfigPath();
    mkdirSync(dirname(path), { recursive: true });
    writeFileSync(path, JSON.stringify({ ...(read(path) ?? {}), style }, null, 2) + "\n");
    return path;
  }
  const path = join(where.dir ?? process.cwd(), "package.json");
  if (!existsSync(path)) throw new Error(`No package.json in ${dirname(path)}; use --global, or run this in a project.`);
  const text = readFileSync(path, "utf8"), pkg = JSON.parse(text);
  const indent = text.match(/^[ \t]+(?=")/m)?.[0] ?? "  ";
  pkg["bun-tsu"] = { ...(pkg["bun-tsu"] ?? {}), style };
  writeFileSync(path, JSON.stringify(pkg, null, indent) + "\n");
  return path;
}
