import data from "../data/known-bad.json";

export type Compromise = { incident: string; url: string };
const index = new Map<string, Compromise>();
for (const [incident, { url, packages }] of Object.entries(data.incidents))
  for (const [name, versions] of Object.entries(packages as Record<string, string[]>))
    for (const v of versions) index.set(`${name}@${v}`, { incident, url });

export const knownBad = (name: string, version: string) => index.get(`${name}@${version}`);
export const knownBadCount = index.size;
