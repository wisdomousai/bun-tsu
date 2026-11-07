// Bun Tsu as a Bun security scanner: add to bunfig.toml
//   [install.security]
//   scanner = "@wisdomousai/bun-tsu"   (the package root exports `scanner`)
// Fatal: exact versions from documented compromises.
// Warn: typosquat-looking names that are direct dependencies or new arrivals (not yet in bun.lock).
// Env: BUN_TSU_STRICT=1 also warns on 'latest'/'*' and git/URL sources. BUN_TSU_QUIET=1 silences the art.
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { knownBad } from "./lib/knownbad.ts";
import { imitates } from "./lib/classify.ts";
import { quoteOfTheDay } from "./lib/quotes.ts";
import { mini, c } from "./lib/art.ts";
import { resolvedVersions } from "./lib/scout.ts";

function directDeps(): Set<string> {
  try {
    const pkg = JSON.parse(readFileSync(join(process.cwd(), "package.json"), "utf8"));
    return new Set(["dependencies", "devDependencies", "optionalDependencies"].flatMap(g => Object.keys(pkg[g] ?? {})));
  } catch { return new Set(); }
}

export const scanner: Bun.Security.Scanner = {
  version: "1",
  async scan({ packages }) {
    const advisories: Bun.Security.Advisory[] = [];
    const direct = directDeps();
    const locked = resolvedVersions(process.cwd());
    const watch = (name: string) => direct.has(name) || !locked.has(name);
    const strict = !!process.env.BUN_TSU_STRICT;
    for (const pkg of packages) {
      const hit = knownBad(pkg.name, pkg.version);
      if (hit) { advisories.push({ level: "fatal", package: pkg.name, url: hit.url,
        description: `Bun Tsu: "The one who came as ${pkg.name}@${pkg.version} wears stolen armour." This exact version was published by an attacker (${hit.incident}).` }); continue; }
      if (watch(pkg.name)) {
        const near = imitates(pkg.name);
        if (near) advisories.push({ level: "warn", package: pkg.name, url: null,
          description: `Bun Tsu: "${pkg.name} wears the face of ${near}, but a letter was lost on the road." Possible typosquat of ${near}.` });
        else if (strict && /^(latest|\*|)$/.test(pkg.requestedRange ?? "")) advisories.push({ level: "warn", package: pkg.name, url: null,
          description: `Bun Tsu: "'${pkg.requestedRange || "*"}' is not a version. It is a prayer." Pin ${pkg.name}.` });
        else if (strict && /^(github:|https?:|git)/.test(pkg.version)) advisories.push({ level: "warn", package: pkg.name, url: null,
          description: `Bun Tsu: "Supplies from a roadside wagon carry no granary seal." ${pkg.name} comes from ${pkg.version.split("#")[0]}, not the registry.` });
      }
    }
    if (!process.env.BUN_TSU_QUIET && process.stderr.isTTY) {
      const line = advisories.length
        ? c.seal(`Bun Tsu has read ${packages.length} packages and sees ${advisories.length} omen(s).`)
        : c.grey(`Bun Tsu has read ${packages.length} packages. \u201C${quoteOfTheDay().q}\u201D`);
      console.error(mini(line) + "\n");
    }
    return advisories;
  },
};

export default scanner;
