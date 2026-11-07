// Turns a scout report into a cryptic prophecy plus a plain translation.
import type { Finding, Report } from "./scout.ts";
import { pick, type Quote } from "./quotes.ts";

const any = <T>(xs: T[]) => xs[Math.floor(Math.random() * xs.length)];
const short = (s: string) => s.split(",")[0].trim();

const VERSES: Record<string, ((f: Finding) => string)[]> = {
  "known-compromise": [
    f => `The one who came to you as ${short(f.subject)} was not ${short(f.subject).split("@")[0]} at all, but an enemy wearing his armour for a single afternoon. You let him in during that afternoon.`,
    f => `${short(f.subject)}: the scrolls of the past already record this traitor's name. Only you have not read them.`,
  ],
  "shady-install-script": [
    f => `You welcomed ${f.subject} as a guest. Before you had read his letter of introduction, he turned his own key in your door.`,
    f => `${f.subject} does not wait to be called. He acts in the hour of installing, when no sentry is posted.`,
  ],
  "typosquat-suspect": [
    f => `The stranger who calls himself ${f.subject} wears the face of your friend ${f.imitates}, but a letter was lost on the road.`,
    f => `${f.subject} stands where ${f.imitates} should stand, and answers to a name that is almost right.`,
  ],
  "committed-token": [
    f => `Your general's seal lies on the tavern table, in the place called ${f.subject}. Whoever lifts it may speak with your voice to the great registry.`,
    f => `In ${f.subject} you have written the password to the armoury on the outside of the armoury.`,
  ],
  "env-unignored": [
    f => `A map of the treasury hangs at the town gate, in the scroll called ${f.subject}. One careless commit, and every traveller may read it.`,
  ],
  "no-lockfile": [
    () => `You keep no map of the ground you stand on. When the terrain shifts in the night, you will not know which night it was.`,
    () => `Each time your army assembles, different soldiers answer the call, and you count only their number.`,
  ],
  "loose-ranges": [() => `Your treaties all end with the words "or any later king". Kings change.`],
  "wild-version": [
    f => `You have sworn loyalty to whatever ${f.subject} is crowned tomorrow, without knowing who will hold the crown.`,
    f => `For ${f.subject} you wrote no version, only a prayer.`,
  ],
  "remote-source": [
    f => `${f.subject} was bought from a wagon by the roadside, not from the granary. The wagon may be repainted every night.`,
  ],
  "shady-script": [
    f => `The courier called ${f.subject.replace("scripts.", "")} reads aloud, with your authority, whatever letter a stranger hands him.`,
  ],
  "deprecated": [
    f => `${f.subject} is a fortress whose garrison has marched away. The first to arrive will hold it, and he will not be you.`,
  ],
  "known-vuln": [
    f => `The crack in the wall named ${f.subject} is already drawn on the enemy's maps.`,
  ],
  "dependency-confusion-risk": [
    f => `Your private regiments, ${short(f.subject)} among them, march without banners. An outsider may claim their name at the border, and be let through.`,
  ],
  "trusted-install-script": [f => `You have granted ${f.subject} the right to strike first. Be sure he strikes only at stone.`],
  "multiple-lockfiles": [() => `Two generals give your army two sets of orders, and both are obeyed.`],
};

const OPENINGS: Record<string, string> = {
  auth: "The gatekeeper is the first one the enemy courts.",
  crypto: "The locksmiths in your service have not all shown their faces.",
  web3: "Your treasury is the target. Every road in your camp leads to it.",
  http: "Your city has many gates, and couriers pass through all of them.",
  build: "Your cooks touch every dish before it reaches the table.",
  database: "The vault is deep, and the enemy knows its address.",
  ui: "You are a city of artisans, and artisans trust their tools.",
  test: "Your drill sergeants carry the keys to the armoury.",
  lint: "Your scribes read every word you write, on every save.",
  logging: "Your scribes remember everything said in the camp.",
  cli: "Your heralds speak in many colours.",
  config: "Whoever changes your order of battle commands your army.",
  native: "Foreign smiths forge parts of your armour in a tongue you cannot read.",
  types: "You have many interpreters, and few have been questioned.",
  other: "The camp is quiet. Quiet is not the same as safe.",
};

export type Prophecy = { title: string; opening: string; verses: Verse[]; closing: Quote; serene: boolean };
const NUMERALS = ["I", "II", "III", "IV", "V", "VI", "VII"];
export const numeral = (i: number) => NUMERALS[i] ?? String(i + 1);

export function dominantType(r: Report): string {
  const ranked = Object.entries(r.profile).filter(([k]) => k !== "other").sort((a, b) => b[1].length - a[1].length);
  // the treasury outranks the kitchen
  for (const hot of ["web3", "auth", "crypto"]) if (r.profile[hot]?.length) return hot;
  return ranked[0]?.[0] ?? "other";
}

export type Verse = { omen: string; finding: Finding; also: Finding[] };
const PREFER = ["known-compromise", "typosquat-suspect", "shady-install-script", "committed-token"];

export function prophesy(r: Report, max = 6): Prophecy {
  // group findings by package/file, keeping severity order
  const groups = new Map<string, Finding[]>();
  for (const f of r.findings) if (f.severity !== "info" && VERSES[f.category]) {
    const key = f.subject.startsWith("@") ? f.subject.split("@").slice(0, 2).join("@") : f.subject.split("@")[0];
    (groups.get(key) ?? groups.set(key, []).get(key)!).push(f);
  }
  const cands = [...groups.values()].map(fs => {
    const lead = PREFER.map(cat => fs.find(f => f.category === cat)).find(Boolean) ?? fs[0];
    return { lead: { ...lead, severity: fs[0].severity }, also: fs.filter(f => f !== lead) };
  });
  // spread across vectors: at most two per vector, then fill
  const chosen: typeof cands = []; const perVector: Record<string, number> = {};
  for (const pass of [2, Infinity]) for (const cnd of cands) {
    if (chosen.length >= max || chosen.includes(cnd)) continue;
    if ((perVector[cnd.lead.vector] ?? 0) < pass) { chosen.push(cnd); perVector[cnd.lead.vector] = (perVector[cnd.lead.vector] ?? 0) + 1; }
  }
  const ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 } as const;
  chosen.sort((a, b) => ORDER[a.lead.severity] - ORDER[b.lead.severity]);
  const omens = chosen.map(x => x.lead);
  const dom = dominantType(r);
  const serene = omens.length === 0;
  const top = omens[0];
  const closing = serene ? pick({ type: dom === "other" ? undefined : dom, vector: "general" })[0] : pick({ vector: top.vector, type: top.types[0] ?? dom })[0];
  return {
    title: `The Scroll of Bun Tsu, concerning ${r.project}`,
    opening: serene ? "The walls are high, the gate is watched, and the map is current." : (OPENINGS[dom] ?? OPENINGS.other) + (top.severity === "critical" ? " And the enemy is already inside." : ""),
    verses: chosen.map(x => ({ omen: any(VERSES[x.lead.category])(x.lead), finding: x.lead, also: x.also })),
    closing,
    serene,
  };
}
