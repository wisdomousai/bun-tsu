---
name: bun-tsu
description: Checks npm packages for supply-chain risk with the Bun Tsu scanner. Use before adding, upgrading or running (npx/bunx) any npm package, to vet it for malware, made-up names, typosquats, suspicious new releases, known advisories and outdated majors. Also use when the user asks to scan or audit a JavaScript project's dependencies, asks for Bun Tsu, a dependency prophecy, or a Sun Tzu / Bun Tsu quote.
---

# Bun Tsu

Bun Tsu has three modes. Pick the mode from the request.

- **Guard**: you are about to add, upgrade or run an npm package. Check it first.
- **Report**: the user wants their project's dependencies checked. Run the scout and report the findings plainly. Use the prophecy or claudish style instead only when the scout's `style` says so or the user asks for it.
- **Oracle**: the user wants a saying. Run the quote command and show the result.

All modes use `bunx @wisdomousai/bun-tsu` and need Bun 1.3 or later. If `bunx` is missing, tell the user to install Bun from https://bun.sh and stop. Do not reproduce the checks by hand.

The checks query OSV.dev and the npm registry. Without network access they fall back to a small built-in list; say so when the output reports `intel-unavailable` or `offline`.

## Guard

1. Before you run `bun add`, `npm install <pkg>`, `pnpm add`, `yarn add`, `npx`, `bunx` or similar, check every package you are about to name:

   ```sh
   bunx @wisdomousai/bun-tsu check --json <pkg[@range]> [...]
   ```

2. Each result has a `verdict`:
   - `block`: malware, a documented compromised version, or a name that does not exist on npm. Do not install it. A missing name usually means you guessed it; look up the real name in the library's docs.
   - `ask`: typosquat-like name, new or little-used package, a release from the last 72 hours, dropped provenance, a new publisher, an added install script, a deprecated package or an advisory of medium severity or worse. Tell the user what was found and let them decide.
   - `note`: low-severity items, such as an older major than the latest. Prefer the current major unless the project pins an older one on purpose.
   - `ok`: install it.

3. Prefer exact, current versions. Do not pin a version from memory without checking it.

If the Bun Tsu Claude Code plugin is installed, a hook runs this check on install commands automatically and blocks or asks for you. Follow its result; do not work around it with another package manager or a different spelling.

## Report

1. Run the scout on the project root (or the folder the user named):

   ```sh
   bunx @wisdomousai/bun-tsu scout --json <dir>
   ```

   Add `--offline` only when the user asks for no network access.

2. Read the JSON. Each entry in `findings` has `severity`, `category`, `vector`, `types`, `subject`, `detail`, `fix` and sometimes `imitates` and `url`. `profile` groups the declared packages by purpose. `intel` says what was checked online. `style` is the user's output style: `plain` (the default), `prophecy` or `claudish`.

3. With the `plain` style, write:
   - One line on what was checked, from `declared`, `resolved` and `intel`.
   - A table, most severe first: number, severity, subject, problem (from `detail`), what to do (from `fix`), and the `url` when there is one.
   - The order you recommend for the fixes, critical first. Say which ones change installed packages, and do them only if the user agrees.
   - How many `low` and `info` findings were left out, if you left any out.

   With no findings above `info`, say that nothing alarming was found, in one or two sentences.

## Prophecy

Use this only when the scout's `style` is `prophecy` or the user asks for a prophecy. The user sets the style with `bunx @wisdomousai/bun-tsu config style prophecy` (add `--global` for every repo).

1. Run the scout as in Report.

2. Get a closing saying that matches the most severe finding:

   ```sh
   bunx @wisdomousai/bun-tsu quote --json --vector <vector> --type <first type>
   ```

   With no findings above `info`, use `--vector general`.

3. Write the scroll:
   - A title: `The Scroll of Bun Tsu, concerning <project>`.
   - One opening line about the kind of project, from `profile` (an auth-heavy project is a gatehouse, a build-heavy one is a kitchen, and so on).
   - Up to six numbered omens in Roman numerals, most severe first. Each omen hints at the package or file in war imagery without naming the fix. Example for a typosquat of `colors`: "The stranger who calls himself colrs wears your friend's face, but a letter was lost on the road."
   - The closing saying with its source exactly as the quote command returned it.

4. Under the scroll, write a section headed `Plain scroll` with the table and fix order from the plain report.

## Claudish

Use this only when the scout's `style` is `claudish` or the user asks for it. It is a parody of AI-generated slop. Get the example text with:

```sh
bunx @wisdomousai/bun-tsu --claudish <dir>
```

Then write the report in that voice: a sycophantic opener, emoji headings (TL;DR, Key Findings, The Bottom Line, Key Takeaways), "This isn't just X. It's Y." for each finding, lists of three, number pairs ("Two critical issues. One mission."), one-line beats ("Let that sink in."), em dashes, bold words, and a closing offer to do more. Every finding, detail, fix and URL stays exact; only the wrapping is slop. Keep the parody in this report and write the rest of the conversation normally.

## Oracle

```sh
bunx @wisdomousai/bun-tsu quote --json [--vector V] [--type T] [--source classic|apocrypha] [--n N]
```

Show each saying in quotes with its source. `bunx @wisdomousai/bun-tsu tags --json` lists the valid vectors and types.

## Rules

- Every omen and every warning comes from a real finding. Do not add threats the scanner did not report.
- In the prophecy style, a project with no findings above `info` gets a calm prophecy and a short note that nothing alarming was found.
- Never print secret values. The scout reports only the file that holds a token; keep it that way.
- Sayings marked "Sun Tzu" come from the Lionel Giles translation. Never attribute a new line to Sun Tzu.
- The scout and the check only read. Do not install, remove or upgrade packages to fix findings unless the user asks.
