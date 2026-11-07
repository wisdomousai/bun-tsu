// bun run build:site  ->  docs/index.html and docs/art/ (GitHub Pages: serve from /docs)
import { readdirSync, mkdirSync, copyFileSync } from "node:fs";

const html = await Bun.file(new URL("../src/site.html", import.meta.url)).text();
const quotes = await Bun.file(new URL("../src/data/quotes.json", import.meta.url)).text();
const safe = quotes.replace(/</g, "\\u003c");
await Bun.write(new URL("../docs/index.html", import.meta.url), html.replace("__QUOTES__", () => safe));

// painted layers (ink-wash WebP cut-outs) live in art/ and are served from docs/art/
const art = new URL("../art/", import.meta.url).pathname, out = new URL("../docs/art/", import.meta.url).pathname;
mkdirSync(out, { recursive: true });
const files = readdirSync(art).filter(f => f.endsWith(".webp"));
for (const f of files) copyFileSync(art + f, out + f);
console.log(`docs/index.html written, ${files.length} images copied to docs/art/`);
