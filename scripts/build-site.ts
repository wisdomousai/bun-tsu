// bun run build:site  ->  docs/index.html (single file, GitHub Pages: serve from /docs)
const html = await Bun.file(new URL("../src/site.html", import.meta.url)).text();
const quotes = await Bun.file(new URL("../src/data/quotes.json", import.meta.url)).text();
const safe = quotes.replace(/</g, "\\u003c");
await Bun.write(new URL("../docs/index.html", import.meta.url), html.replace("__QUOTES__", () => safe));
console.log("docs/index.html written");
