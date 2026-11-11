// bun run build:site  ->  site/dist/ (the Pages workflow uploads it)
// index.html gets the quotes from the scanner's data inlined; art/*.webp are the painted ink-wash cut-outs.
import { readdirSync, mkdirSync, copyFileSync } from "node:fs";

const at = (p: string) => new URL(p, import.meta.url).pathname;
const html = await Bun.file(at("index.html")).text();
const quotes = await Bun.file(at("../src/data/quotes.json")).text();
const safe = quotes.replace(/</g, "\\u003c");
await Bun.write(at("dist/index.html"), html.replace("__QUOTES__", () => safe));

mkdirSync(at("dist/art/"), { recursive: true });
const files = readdirSync(at("art/")).filter(f => f.endsWith(".webp"));
for (const f of files) copyFileSync(at("art/") + f, at("dist/art/") + f);
console.log(`site/dist/index.html written, ${files.length} images copied to site/dist/art/`);
