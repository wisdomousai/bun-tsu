# Bun Tsu

Is your cybersecurity team giving you cryptic requirements that you can't really understand, but they sound really important? Bun Tsu can help you automate this!

## Sample output

A small API project with `expresss` instead of `express`, `lodash` at `*`, a GitHub branch dependency, `debug` locked at the compromised 4.4.2, an old `jsonwebtoken`, a token in `.npmrc` and an unignored `.env`.

```console
$ bunx @wisdomousai/bun-tsu

  Bun Tsu report for shop-api
  Checked 5 declared dependencies and 2 resolved versions (osv: 2 versions, registry: 4/4 direct deps).
  Found 2 critical, 5 high, 1 medium, 2 low, 1 info. Most severe first; each item says what to do.

  1. CRITICAL debug@4.4.2
     Problem (known-compromise): This exact version was published by an
     attacker (chalk, debug and friends (Sept 2025)).
     Action: Remove debug@4.4.2, reinstall a clean version, rotate any
     secrets on machines or builds that ran it, and rebuild bundles.
     See: https://semgrep.dev/blog/2025/chalk-debug-and-color-on-npm-compromised-in-new-supply-chain-attack
     Problem (version-unpublished): npm no longer serves debug@4.4.2.
     Versions are usually pulled for malware or a broken release.
     Action: Move to a version npm still publishes and find out why 4.4.2
     was removed.

  2. CRITICAL .npmrc
     Problem (committed-token): Contains a literal registry auth token.
     Action: Revoke it, reference `${NPM_TOKEN}` instead, and scrub git
     history.

  3. HIGH lodash
     Problem (wild-version): Version "*" in dependencies accepts any future
     release, including a hijacked one.
     Action: Pin lodash to a known version.

  4. HIGH expresss
     Problem (typosquat-suspect): Name is one edit away from the popular
     package "express".
     Action: Confirm expresss is intended (registry page, maintainer,
     downloads); otherwise replace it with express.

  5. HIGH jsonwebtoken@8.5.1
     Problem (known-vuln): 3 advisories; worst: jsonwebtoken unrestricted
     key type could lead to legacy keys usage (GHSA-8cf7-32gw-wr33).
     Action: Upgrade jsonwebtoken to 9.0.0 or later.
     See: https://osv.dev/vulnerability/GHSA-8cf7-32gw-wr33
     Problem (outdated): Resolved 8.5.1; latest is 9.0.3. Old major
     versions stop getting security fixes.
     Action: Plan an upgrade to jsonwebtoken@9.0.3.

  6. HIGH .env
     Problem (env-unignored): .env exists and .gitignore doesn't exclude
     .env files.
     Action: Add `.env*` to .gitignore; if it was ever committed, rotate
     those secrets.

  7. MEDIUM payments-sdk
     Problem (remote-source): Installed from
     "github:someone/payments-sdk#main", bypassing the registry; branch
     refs can change silently.
     Action: Use a registry release, or pin to a full commit SHA.

  8. LOW expresss@0.0.0
     Problem (unmaintained): No release of expresss in 10 years. Abandoned
     packages are a target for account takeover.
     Action: Look for a maintained alternative, or vendor it.

  1 info finding(s) not shown; add --all to include them.
```

The CLI needs Bun 1.3 or later.

## Usage

**1. The report (CLI)**

```sh
bunx @wisdomousai/bun-tsu                 # check this project: problems and what to do
bunx @wisdomousai/bun-tsu --prophecy      # the same, as Bun Tsu's scroll first
bunx @wisdomousai/bun-tsu quote --vector typosquat --type auth
bunx @wisdomousai/bun-tsu tags            # every attack vector and package type
bunx @wisdomousai/bun-tsu scout --json    # raw findings, for agents and CI
bunx @wisdomousai/bun-tsu --strict        # exit 1 on anything critical or high (CI)
bunx @wisdomousai/bun-tsu --offline       # no network: built-in compromise list only
bunx @wisdomousai/bun-tsu check zod@^4 left-pad   # vet packages before installing them
```

`check` gives each package a verdict: `block` (malware, a documented compromised version, or a name that doesn't exist on npm), `ask` (something a human should look at), `note` or `ok`. It exits 1 when anything is blocked.

**2. At the gate of every install (Bun security scanner)**

Bun 1.3+ lets a package inspect everything `bun install` is about to fetch. Make Bun Tsu that package:

```sh
bun add -d @wisdomousai/bun-tsu
bunx bun-tsu init            # writes [install.security] scanner = "@wisdomousai/bun-tsu"
```

From then on, `bun install`, `bun add` and friends pass before him:

- **fatal** (install stops): any version OSV.dev lists as malware, and exact versions from the built-in list of documented compromises (event-stream 3.3.6, ua-parser-js 0.7.29, chalk 5.6.1 / debug 4.4.2, ...).
- **warn** (prompt in a terminal, cancel in CI): new or direct dependencies whose names are one letter from a popular package, and new arrivals (not yet in `bun.lock`) that were published in the last 72 hours, dropped provenance, or added an install script the previous release didn't have.
- With `BUN_TSU_STRICT=1`, also warns on critical advisories, `latest` / `*` and git or URL sources.
- `BUN_TSU_OFFLINE=1` skips the network. If OSV can't be reached, the install continues with only the built-in list, and a line says so.
- Messages are plain instructions. In the prophecy style each starts with an omen, and a line of art follows the scan; `BUN_TSU_QUIET=1` silences the art.

**3. In front of your coding agent (Claude Code plugin)**

Agents install packages from memory. They pick old majors, misspell names, and sometimes invent names that an attacker can register. The plugin checks every package an agent is about to install:

```sh
/plugin marketplace add wisdomousai/bun-tsu
/plugin install bun-tsu@bun-tsu
```

- **PreToolUse hook (Bash)**: when the agent runs `bun add`, `npm install <pkg>`, `pnpm add`, `yarn add`, `npx`, `bunx` or `pnpm dlx`, each package goes through `check`. `block` denies the command and tells the agent why. `ask` puts the findings in front of you to approve. Low-severity notes, such as "latest is 4.x", go to the agent as context. Other commands pass through in a few milliseconds.
- **SessionStart hook**: on startup, `/clear` and compaction, the agent gets the project's critical, high and medium findings (offline checks plus OSV; no registry calls, so it stays fast).
- **Skill**: `bun-tsu` tells the agent to vet packages before installing, to read the scout's JSON, and to write the prophecy on request.

The hooks run `src/hook.ts` from the plugin with `bun`, so Bun 1.3+ must be on the PATH. Without the plugin system, `bunx bun-tsu init --claude` writes the same two hooks into `.claude/settings.json` (they then run through `bunx`).

**4. A saying a day (preload)**


```sh
bunx bun-tsu init --preload  # adds preload = ["@wisdomousai/bun-tsu/preload"]
```

Prints one saying, once a day, on interactive `bun run`. Silent in CI and pipes.

## Prophecy style

The report is plain by default. The prophecy style puts Bun Tsu's scroll in front of it: each finding becomes an omen, and a Sun Tzu or Bun Tsu saying closes it. The same project, offline:

```console
$ bunx @wisdomousai/bun-tsu --prophecy --no-art --offline
  (@)==================================================================(@)
    |                                                                  |
    | The Scroll of Bun Tsu, concerning shop-api                       |
    | ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~                       |
    |                                                                  |
    | The gatekeeper is the first one the enemy courts. And the enemy  |
    | is already inside.                                               |
    |                                                                  |
    | I. debug@4.4.2: the scrolls of the past already record this      |
    | traitor's name. Only you have not read them.                     |
    |                                                                  |
    | II. In .npmrc you have written the password to the armoury on    |
    | the outside of the armoury.                                      |
    |                                                                  |
    | III. You have sworn loyalty to whatever lodash is crowned        |
    | tomorrow, without knowing who will hold the crown.               |
    |                                                                  |
    | IV. The stranger who calls himself expresss wears the face of    |
    | your friend express, but a letter was lost on the road.          |
    |                                                                  |
    | V. A map of the treasury hangs at the town gate, in the scroll   |
    | called .env. One careless commit, and every traveller may read   |
    | it.                                                              |
    |                                                                  |
    | VI. payments-sdk was bought from a wagon by the roadside, not    |
    | from the granary. The wagon may be repainted every night.        |
    |                                                                  |
    | “Trust is earned over many versions and spent in one.” — Bun Tsu |
    |                                                                  |
  (@)==================================================================(@)
   |                                                                    |
   #                                                                    #
   V                                                                    V

  The plain scroll  (5 declared, 1 resolved, offline, profile: auth)

  I   CRITICAL debug@4.4.2  malicious-update
              This exact version was published by an attacker (chalk, debug and
              friends (Sept 2025)).
              → Remove debug@4.4.2, reinstall a clean version, rotate any
              secrets on machines or builds that ran it, and rebuild bundles.
              https://semgrep.dev/blog/2025/chalk-debug-and-color-on-npm-compromised-in-new-supply-chain-attack

  II  CRITICAL .npmrc  leaked-secrets
              Contains a literal registry auth token.
              → Revoke it, reference `${NPM_TOKEN}` instead, and scrub git
              history.

  III HIGH     lodash  version-drift
              Version "*" in dependencies accepts any future release, including
              a hijacked one.
              → Pin lodash to a known version.

  IV  HIGH     expresss  typosquat
              Name is one edit away from the popular package "express".
              → Confirm expresss is intended (registry page, maintainer,
              downloads); otherwise replace it with express.

  V   HIGH     .env  leaked-secrets
              .env exists and .gitignore doesn't exclude .env files.
              → Add `.env*` to .gitignore; if it was ever committed, rotate
              those secrets.

  VI  MEDIUM   payments-sdk  remote-source
              Installed from "github:someone/payments-sdk#main", bypassing the
              registry; branch refs can change silently.
              → Use a registry release, or pin to a full commit SHA.
```

Without `--no-art` the general appears above the scroll and a seal stamps it at the end.

Turn it on per run, per repo, or everywhere:

```sh
bunx @wisdomousai/bun-tsu --prophecy                       # this run (--plain forces plain)
bunx @wisdomousai/bun-tsu config style prophecy            # this repo: "bun-tsu": { "style": "prophecy" } in package.json
bunx @wisdomousai/bun-tsu config style prophecy --global   # every repo: ~/.config/bun-tsu/config.json
BUN_TSU_STYLE=prophecy bunx @wisdomousai/bun-tsu           # environment
bunx @wisdomousai/bun-tsu config                           # show the style in effect and where it came from
```

The flag wins over the environment, the environment over the repo, and the repo over the global file. The style also applies to the Bun install scanner's messages, and the agent skill writes the scroll when the style is `prophecy`. The agent hooks always report plainly.

## What the scout checks

- Lockfiles: missing, multiple, or binary.
- Version specs: `*`, `latest`, git/URL sources, loose ranges with no lockfile.
- Typosquat-looking names.
- Install scripts that fetch or eval code, and your `trustedDependencies`.
- Deprecated packages.
- Every resolved version in `bun.lock` / `package-lock.json` / `node_modules` against OSV.dev (malware reports from OpenSSF and GitHub, plus GitHub, npm and NVD advisories), grouped per package with the lowest version that fixes them all. The built-in list of documented compromises is checked too, also offline.
- Each direct dependency's registry history:
  - the name doesn't exist on npm;
  - the resolved version was pulled from npm;
  - it was published in the last 72 hours (`BUN_TSU_FRESH_HOURS` changes this);
  - it lacks the provenance or trusted publishing its previous release had;
  - it adds an install script the previous release didn't have;
  - it was published by someone who never published the package before;
  - the package is under 30 days old;
  - the resolved version is a major behind latest;
  - the package has had no release in two years.
- Literal tokens in `.npmrc` or `bunfig.toml`. Values are never printed.
- `.env` files git isn't ignoring.
- Dependency-confusion risk when a custom registry is configured: unscoped names that are free on public npm.
- Optionally `bun audit` (`--audit`).

Registry and OSV responses are cached for an hour (advisory details for a day) in `~/.cache/bun-tsu`, or `BUN_TSU_CACHE`. `BUN_TSU_REGISTRY` points the registry checks at a mirror.

Each finding carries an attack **vector** (typosquat, install-script, leaked-secrets, ...). Each package gets a purpose **type** (auth, crypto, web3, http, build, database, ...). The scroll's imagery and closing quote come from both.

## Quotes

168 sayings: 33 from Sun Tzu (Lionel Giles' 1910 translation, public domain) and 135 Bun Tsu apocrypha, each tagged by vector and package type. Contributions welcome in `src/data/quotes.json`. Never attribute a new line to Sun Tzu.

## Library

```ts
import { scout, prophesy, pick, scanner } from "@wisdomousai/bun-tsu";
const report = await scout(".");
console.log(prophesy(report).verses.map(v => v.omen));
```

A [wisdomous](https://wisdomous.ai/vibecoding) vibecoding project.

MIT. Bun Tsu catches known malware, guessed names and the release patterns of past npm attacks. It does not analyse package code, so a new attack with none of those signs gets through. Use it next to, not instead of, a code-analysing scanner such as Socket's.

## Agent skill only

To use the skill without the plugin's hooks:

```sh
cp -R skills/bun-tsu ~/.claude/skills/
```

## Publishing

Published as `@wisdomousai/bun-tsu` under the wisdomousai npm scope. Run `bun publish`; `publishConfig.access` is already `public`, which scoped packages need. The `bin` points at a TypeScript file with a `#!/usr/bin/env bun` shebang, so the CLI needs Bun.
