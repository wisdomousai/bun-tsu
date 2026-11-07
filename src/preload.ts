// Optional: preload = ["@wisdomousai/bun-tsu/preload"] in bunfig.toml prints one saying per day, on interactive runs only.
import { existsSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { quoteOfTheDay } from "./lib/quotes.ts";
import { c } from "./lib/art.ts";

const day = new Date().toISOString().slice(0, 10);
const stamp = join(tmpdir(), `bun-tsu-${day}`);
if (process.stderr.isTTY && !process.env.BUN_TSU_QUIET && !process.env.CI && !existsSync(stamp)) {
  const q = quoteOfTheDay();
  console.error(c.bun("  (-_-) ") + c.italic(`\u201C${q.q}\u201D`) + c.grey(`  \u2014 ${q.src.split(",")[0]}`));
  try { writeFileSync(stamp, ""); } catch {}
}
