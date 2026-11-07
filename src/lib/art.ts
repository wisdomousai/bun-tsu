// ASCII art and terminal colour for Bun Tsu. Respects NO_COLOR and non-TTY output.
const useColor = !process.env.NO_COLOR && (process.stdout.isTTY || !!process.env.FORCE_COLOR);
const code = (n: string) => (s: string) => (useColor ? `\x1b[${n}m${s}\x1b[0m` : s);
export const c = {
  dim: code("2"), bold: code("1"), italic: code("3"),
  red: code("31"), yellow: code("33"), green: code("32"), cyan: code("36"), grey: code("90"),
  bun: code("38;5;180"), seal: code("38;5;160"), steam: code("38;5;250"),
};

// The general: a steamed bun for a head, a bamboo book in his hands, a war banner on the
// left, a jian planted on the right, and a distant ridge underfoot. Plain ASCII, 66 columns.
// banner() paints it by position: the first 3 rows are steam, the last 2 are ridge and mist,
// the banner is columns 0-10, the sword is columns 61 and up, the general is in between.
export const SAGE = String.raw`
                                 )     (      )    (
                                (   )   )   (    )   )
                                 )    (    (   )    (
          ^                    _.-~(@)~-._
          |              .-~'/   /  |  \   \'~-.
  ,-------+          .-'   /    /   |   \    \   '-.
 <  ^v^v^v|       .'     /     /    |    \     \     '.
  '-------+     /      /      /     |     \      \      \
          |    |      /      /      |      \      \      |
          |    |=======[#]=========(O)=========[#]=======|
          |    |     \_____                   _____/     |     o
          |    |        .-(o)-.     |     .-(o)-.        |     #
          |    |                   /_\                   |   =-+-=
          |    |         .--~~~--.__^__.--~~~--.         |     |
          |     \               '-.|||.-'               /      |
          |       '.              \|||/              .'        |
          |           '-.__        |||        __.-'            |
          | _.-~~~~~~~-._ /\/\/\/\/\|/\/\/\/\/\ _.-~~~~~~~-._  |
          | / @ @ @ @ @ \ \/\/\/\/\/|\/\/\/\/\/ / @ @ @ @ @ \  |
          | \_._._._._._/           V           \_._._._._._/  |
          |   |  .-====+=========================+====-.  |    |
          | (_)=|:|:|:|:|:|:|:|:|:|:|:|:|:|:|:|:|:|:|:|:|=(_)  |
          | (_)=|:|:|:|:|:|:|:|:|:|:|:|:|:|:|:|:|:|:|:|:|=(_)  |
          |   |  '-====+=========================+====-'  |    |
          |       |====[]==========(@)==========[]====|        |
          |      //\/\/\/\/\/\/\/\/\|/\/\/\/\/\/\/\/\/\\       |
          |     /\/\/\/\/\/\/\/\/\/\|/\/\/\/\/\/\/\/\/\/\      |
          |    '====================|===================='     |
          |               [========] [========]                V
_.--.__/\__.-'~-.___/\_.--._____/\/\___.-'~'-.__/\__.--.___/\_.--.
~~~ ~~~ ~~~ ~~~ ~~~ ~~~ ~~~ ~~~ ~~~ ~~~ ~~~ ~~~ ~~~ ~~~ ~~~ ~~~ ~~`;

export const TITLE = String.raw`
            #####  ##  ## ##  ##     ######  ##### ##  ##
            ##  ## ##  ## ### ##       ##   ##     ##  ##
            #####  ##  ## ######       ##    ####  ##  ##
            ##  ## ##  ## ## ###       ##       ## ##  ##
            #####   ####  ##  ##       ##   #####   ####
`;

// A small bun-general head, 13 columns by 6 rows. The text of mini() sits on the eye row.
export const MINI = String.raw`
   _.(@)._
 .'/ / \ \'.
|==[ (#) ]==|
| -o     o- |
 \  ~-^-~  /
  '-.|||.-'`;

const SAGE_STEAM = 3, SAGE_GROUND = 2, SAGE_BANNER_END = 11, SAGE_SWORD_START = 61, TITLE_INDENT = 12;
const MINI_TEXT_ROW = 3;

export function banner(subtitle = "The Art of Dependency") {
  const rows = SAGE.split("\n").slice(1);
  const paint = (l: string, i: number) => {
    if (i < SAGE_STEAM) return c.steam(l);
    if (i === rows.length - 1) return c.steam(l);
    if (i >= rows.length - SAGE_GROUND) return c.grey(l);
    const seg = (s: string, f: (x: string) => string) => (s ? f(s) : "");
    return seg(l.slice(0, SAGE_BANNER_END), c.seal) + seg(l.slice(SAGE_BANNER_END, SAGE_SWORD_START), c.bun)
      + seg(l.slice(SAGE_SWORD_START), c.cyan);
  };
  const art = rows.map(paint).join("\n");
  return `\n${art}\n${c.bold(c.bun(TITLE))}${" ".repeat(TITLE_INDENT)}${c.italic(c.grey(subtitle))}\n`;
}

export function mini(line: string) {
  const art = MINI.split("\n").slice(1);
  return art.map((l, i) => c.bun(l.padEnd(15)) + (i === MINI_TEXT_ROW ? line : "")).join("\n");
}

const strip = (s: string) => s.replace(/\x1b\[[0-9;]*m/g, "");
export function wrap(text: string, width: number) {
  const out: string[] = []; let line = "";
  for (const w of text.split(/\s+/)) {
    if (strip(line + " " + w).trim().length > width) { out.push(line.trim()); line = w; } else line += " " + w;
  }
  if (line.trim()) out.push(line.trim());
  return out;
}

// A hanging scroll: a rod with knobs top and bottom, paper in between, tassels below.
// The paper is `width - 4` columns wide and sits between the rod knobs; the text is `width - 8` wide.
export function scroll(title: string, paragraphs: string[], width = Math.min(72, (process.stdout.columns || 80) - 4)) {
  const inner = width - 8;
  const rod = c.bun("(@)" + "=".repeat(width - 6) + "(@)");
  const edge = c.bun("|");
  const row = (s = "") => "  " + edge + " " + s + " ".repeat(Math.max(0, inner - strip(s).length)) + " " + edge;
  const tassel = (ch: string) => c.seal(" " + ch + " ".repeat(width - 4) + ch);
  const lines = [rod, row(), row(c.bold(title)), row(c.grey("~".repeat(strip(title).length))), row()];
  for (const p of paragraphs) { for (const l of wrap(p, inner)) lines.push(row(l)); lines.push(row()); }
  lines.push(rod, tassel("|"), tassel("#"), tassel("V"));
  return lines.map(l => "  " + l).join("\n");
}

// A square seal: double border, the characters for "bun" and "soldier" (2 columns each), then the text.
export function seal(text = "BUN TSU") {
  let inner = text.length + 2;
  if (inner % 2 === 0) inner++;
  const centre = (s: string, w: number) => " ".repeat(Math.floor((w - s.length) / 2)) + s + " ".repeat(Math.ceil((w - s.length) / 2));
  const glyphs = "\u5305 \u5175"; // 5 display columns: 2 + 1 + 2
  const glyphRow = " ".repeat(Math.floor((inner - 5) / 2)) + glyphs + " ".repeat(Math.ceil((inner - 5) / 2));
  return c.seal([
    "+" + "=".repeat(inner + 2) + "+",
    "|+" + "-".repeat(inner) + "+|",
    "||" + glyphRow + "||",
    "||" + centre(text, inner) + "||",
    "|+" + "-".repeat(inner) + "+|",
    "+" + "=".repeat(inner + 2) + "+",
  ].join("\n"));
}
