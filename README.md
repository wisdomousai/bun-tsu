# Bun Tsu

Is your cybersecurity team giving you cryptic requirements that you can't really understand, but they sound really important? Bun Tsu can help you automate this!

## Sample output

A small API project with `expresss` instead of `express`, `lodash` at `*`, a GitHub branch dependency, `debug` locked at the compromised 4.4.2, a token in `.npmrc` and an unignored `.env`.

```console
$ bunx @wisdomousai/bun-tsu --no-art
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

  The plain scroll  (5 declared, 1 resolved, profile: auth)

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

The CLI needs Bun 1.3 or later.

## Usage

**1. The prophecy (CLI)**

```sh
bunx @wisdomousai/bun-tsu                 # read this project, deliver the scroll
bunx @wisdomousai/bun-tsu quote --vector typosquat --type auth
bunx @wisdomousai/bun-tsu tags            # every attack vector and package type
bunx @wisdomousai/bun-tsu scout --json    # raw findings, for agents and CI
bunx @wisdomousai/bun-tsu --strict        # exit 1 on anything critical or high (CI)
```

**2. At the gate of every install (Bun security scanner)**

Bun 1.3+ lets a package inspect everything `bun install` is about to fetch. Make Bun Tsu that package:

```sh
bun add -d @wisdomousai/bun-tsu
bunx bun-tsu init            # writes [install.security] scanner = "@wisdomousai/bun-tsu"
```

From then on, `bun install`, `bun add` and friends pass before him:

- **fatal** (install stops): exact versions from documented npm compromises, such as event-stream 3.3.6, ua-parser-js 0.7.29 and chalk 5.6.1 / debug 4.4.2 from September 2025.
- **warn** (prompt in a terminal, cancel in CI): new or direct dependencies whose names are one letter from a popular package.
- With `BUN_TSU_STRICT=1`, also warns on `latest` / `*` and git or URL sources.
- `BUN_TSU_QUIET=1` silences the art.

The known-bad list is a small, hand-checked sample (`src/data/known-bad.json`), not a threat feed. For real protection, pair it with a maintained scanner such as Socket's.

**3. A saying a day (preload)**

```sh
bunx bun-tsu init --preload  # adds preload = ["@wisdomousai/bun-tsu/preload"]
```

Prints one saying, once a day, on interactive `bun run`. Silent in CI and pipes.

## What the scout checks

- Lockfiles: missing, multiple, or binary.
- Version specs: `*`, `latest`, git/URL sources, loose ranges with no lockfile.
- Typosquat-looking names.
- Install scripts that fetch or eval code, and your `trustedDependencies`.
- Deprecated packages.
- Resolved versions in `bun.lock` / `package-lock.json` / `node_modules` against documented compromises.
- Literal tokens in `.npmrc` or `bunfig.toml`. Values are never printed.
- `.env` files git isn't ignoring.
- Dependency-confusion risk when a custom registry is configured.
- Optionally `bun audit` (`--audit`).

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

MIT. Not a substitute for actual security tooling, only a more entertaining reason to use it.

## Agent skill

`skill/bun-tsu/SKILL.md` is a Claude agent skill for the prophecy and the quotes. Install it for Claude Code:

```sh
cp -R skill/bun-tsu ~/.claude/skills/
```

## Publishing

Published as `@wisdomousai/bun-tsu` under the wisdomousai npm scope. Run `bun publish`; `publishConfig.access` is already `public`, which scoped packages need. The `bin` points at a TypeScript file with a `#!/usr/bin/env bun` shebang, so the CLI needs Bun.
