// Bun Tsu as a Bun security scanner: add to bunfig.toml
//   [install.security]
//   scanner = "@wisdomousai/bun-tsu"   (the package root exports `scanner`)
// Fatal: malware reported to OSV, and exact versions from the built-in list of documented compromises.
// Warn: typosquat-looking names, and new arrivals (not yet in bun.lock) that were published in the last 72 hours,
//       dropped provenance or added an install script.
// Messages are plain instructions; the prophecy style (see lib/config.ts) adds an omen, the claudish style adds slop.
// Env: BUN_TSU_STRICT=1 also warns on critical advisories, 'latest'/'*' and git/URL sources.
//      BUN_TSU_OFFLINE=1 skips the network. BUN_TSU_QUIET=1 silences the art.
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { knownBad } from "./lib/knownbad.ts";
import { imitates } from "./lib/classify.ts";
import { quoteOfTheDay } from "./lib/quotes.ts";
import { mini, c } from "./lib/art.ts";
import { resolvedVersions } from "./lib/scout.ts";
import { osv, packument, pool } from "./lib/registry.ts";
import { signals } from "./lib/signals.ts";
import { resolveStyle } from "./lib/config.ts";

const RELEASE_WARN = new Set(["fresh-release", "provenance-dropped", "install-script-added", "version-unpublished"]);

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
    const flagged = new Set<string>();
    const push = (a: Bun.Security.Advisory) => { advisories.push(a); flagged.add(a.package); };
    const direct = directDeps();
    const locked = resolvedVersions(process.cwd());
    const arriving = (p: { name: string; version: string }) => !locked.get(p.name)?.has(p.version);
    const strict = !!process.env.BUN_TSU_STRICT;
    const { style } = resolveStyle(process.cwd()), prophecy = style === "prophecy";
    const say = (text: string, omen: string) => prophecy ? `Bun Tsu: "${omen}" ${text}`
      : style === "claudish" ? `Bun Tsu: Great catch! 🎯 ${text} This isn't just a warning — it's a wake-up call. Let that sink in. 🚨` : `Bun Tsu: ${text}`;
    const registry = packages.filter(p => /^\d+\.\d+\.\d+/.test(p.version));
    const vulns = await osv(registry.map(p => ({ name: p.name, version: p.version })));

    for (const pkg of packages) {
      const hit = knownBad(pkg.name, pkg.version);
      if (hit) { push({ level: "fatal", package: pkg.name, url: hit.url,
        description: say(`${pkg.name}@${pkg.version} was published by an attacker (${hit.incident}). Do not install it; use another version.`, `The one who came as ${pkg.name}@${pkg.version} wears stolen armour.`) }); continue; }
      const found = vulns?.get(`${pkg.name}@${pkg.version}`) ?? [];
      const mal = found.find(v => v.malicious);
      if (mal) { push({ level: "fatal", package: pkg.name, url: mal.url,
        description: say(`${pkg.name}@${pkg.version} is reported as malware: ${mal.summary} (${mal.id}). Do not install it.`, `${pkg.name}@${pkg.version} is listed in the enemy's own muster rolls.`) }); continue; }
      const crit = strict && found.find(v => v.severity === "critical");
      if (crit) push({ level: "warn", package: pkg.name, url: crit.url,
        description: say(`${crit.summary} (${crit.id}). ${crit.fixed ? `Upgrade ${pkg.name} to ${crit.fixed} or later.` : "No fixed version is listed; see the advisory."}`, "The crack in this wall is already on the enemy's maps.") });
      if (!direct.has(pkg.name) && !arriving(pkg)) continue;
      const near = imitates(pkg.name);
      if (near) push({ level: "warn", package: pkg.name, url: null,
        description: say(`${pkg.name} is one letter away from the popular package ${near}. Check that you meant ${pkg.name} and not ${near}.`, `${pkg.name} wears the face of ${near}, but a letter was lost on the road.`) });
      else if (strict && /^(latest|\*|)$/.test(pkg.requestedRange ?? "")) push({ level: "warn", package: pkg.name, url: null,
        description: say(`${pkg.name} is requested as '${pkg.requestedRange || "*"}', which accepts any future release. Pin a version.`, `'${pkg.requestedRange || "*"}' is not a version. It is a prayer.`) });
      else if (strict && /^(github:|https?:|git)/.test(pkg.version)) push({ level: "warn", package: pkg.name, url: null,
        description: say(`${pkg.name} comes from ${pkg.version.split("#")[0]}, not the registry. Use a registry release or pin a full commit SHA.`, "Supplies from a roadside wagon carry no granary seal.") });
    }

    // release history of new arrivals; on a first install everything is new, so then only direct deps
    const arrivals = registry.filter(p => arriving(p) && !flagged.has(p.name));
    const watch = arrivals.length <= 40 ? arrivals : arrivals.filter(p => direct.has(p.name));
    await pool(watch, 8, async pkg => {
      const p = await packument(pkg.name);
      if (!p || p === "missing") return;
      const s = signals(p, pkg.version).find(x => RELEASE_WARN.has(x.category));
      if (s) push({ level: "warn", package: pkg.name, url: null, description: say(`${s.detail} ${s.fix}`, "A stranger in familiar armour.") });
    });

    const unreachable = !vulns && !process.env.BUN_TSU_OFFLINE;
    if (!prophecy && unreachable) console.error(c.grey("Bun Tsu: OSV was unreachable; only the built-in compromise list was checked."));
    if (prophecy && !process.env.BUN_TSU_QUIET && process.stderr.isTTY) {
      const line = advisories.length
        ? c.seal(`Bun Tsu has read ${packages.length} packages and sees ${advisories.length} omen(s).`)
        : c.grey(`Bun Tsu has read ${packages.length} packages. “${quoteOfTheDay().q}”`);
      console.error(mini(line) + (!unreachable ? "" : "\n" + c.grey("  OSV was unreachable; only the built-in compromise list was checked.")) + "\n");
    }
    return advisories;
  },
};

export default scanner;
