import scroll from "../data/quotes.json";

export type Quote = { q: string; src: string; vectors: string[]; types: string[] };
export const VECTORS = scroll.vectors as Record<string, string>;
export const TYPES = scroll.types as Record<string, string>;
const SRC = { classic: "Sun Tzu, The Art of War (tr. Lionel Giles, 1910)", apocrypha: "Bun Tsu, The Art of Dependency (apocrypha)" };

export function allQuotes(source?: "classic" | "apocrypha"): Quote[] {
  const out: Quote[] = [];
  for (const s of ["classic", "apocrypha"] as const) if (!source || source === s)
    for (const e of (scroll as any)[s]) out.push({ q: e.q, src: SRC[s], vectors: e.vectors ?? ["general"], types: e.types ?? [] });
  return out;
}

/** Random pick preferring vector+type, then vector, then type, then anything. Never empty. */
export function pick(opts: { vector?: string; type?: string; source?: "classic" | "apocrypha"; n?: number; exclude?: string[] } = {}): Quote[] {
  const { vector: v, type: t, n = 1, exclude = [] } = opts;
  const all = allQuotes(opts.source).filter(e => !exclude.includes(e.q));
  const tiers = [
    all.filter(e => v && t && e.vectors.includes(v) && e.types.includes(t)),
    all.filter(e => v && e.vectors.includes(v)),
    all.filter(e => t && e.types.includes(t)),
    all,
  ];
  const picked: Quote[] = [];
  for (const tier of tiers) {
    const pool = tier.filter(e => !picked.includes(e)).sort(() => Math.random() - 0.5);
    while (picked.length < n && pool.length) picked.push(pool.pop()!);
    if (picked.length >= n) break;
  }
  return picked;
}

/** Same quote all day, for the preload hook. */
export function quoteOfTheDay(): Quote {
  const all = allQuotes();
  const day = Math.floor(Date.now() / 86_400_000);
  return all[(day * 2654435761) % all.length];
}
