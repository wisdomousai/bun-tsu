---
name: bun-tsu
description: Reads a JavaScript project's dependencies with the Bun Tsu scout and tells the user, as a cryptic Sun Tzu style prophecy followed by a plain table, how the project could be hacked through its packages. Also gives a single Sun Tzu or Bun Tsu saying on request. Use when the user asks for Bun Tsu, a dependency prophecy, a supply-chain reading of package.json, or a Sun Tzu / Bun Tsu quote.
---

# Bun Tsu

Bun Tsu has two modes. Pick the mode from the request.

- **Prophecy**: the user wants their project read. Run the scout, then write the scroll and the plain table.
- **Oracle**: the user wants a saying. Run the quote command and show the result.

Both modes use `bunx @wisdomousai/bun-tsu` and need Bun 1.3 or later. If `bunx` is missing, tell the user to install Bun from https://bun.sh and stop. Do not reproduce the checks by hand.

## Prophecy

1. Run the scout on the project root (or the folder the user named):

   ```sh
   bunx @wisdomousai/bun-tsu scout --json <dir>
   ```

   Add `--audit` only when the user asks for known advisories. It calls `bun audit` and needs network access.

2. Read the JSON. Each entry in `findings` has `severity`, `category`, `vector`, `types`, `subject`, `detail`, `fix` and sometimes `imitates` and `url`. `profile` groups the declared packages by purpose.

3. Get a closing saying that matches the most severe finding:

   ```sh
   bunx @wisdomousai/bun-tsu quote --json --vector <vector> --type <first type>
   ```

   With no findings above `info`, use `--vector general`.

4. Write the scroll:
   - A title: `The Scroll of Bun Tsu, concerning <project>`.
   - One opening line about the kind of project, from `profile` (an auth-heavy project is a gatehouse, a build-heavy one is a kitchen, and so on).
   - Up to six numbered omens in Roman numerals, most severe first. Each omen hints at the package or file in war imagery without naming the fix. Example for a typosquat of `colors`: "The stranger who calls himself colrs wears your friend's face, but a letter was lost on the road."
   - The closing saying with its source exactly as the quote command returned it.

5. Under the scroll, write a section headed `Plain scroll` with a table: number, severity, subject, problem (from `detail`), what to do (from `fix`). Add the `url` when there is one. Mention how many `info` findings were left out.

## Oracle

```sh
bunx @wisdomousai/bun-tsu quote --json [--vector V] [--type T] [--source classic|apocrypha] [--n N]
```

Show each saying in quotes with its source. `bunx @wisdomousai/bun-tsu tags --json` lists the valid vectors and types.

## Rules

- Every omen comes from a real finding. Do not add threats the scout did not report.
- A project with no findings above `info` gets a calm prophecy and a short note that nothing alarming was found.
- Never print secret values. The scout reports only the file that holds a token; keep it that way.
- Sayings marked "Sun Tzu" come from the Lionel Giles translation. Never attribute a new line to Sun Tzu.
- The scout only reads files. Do not install, remove or upgrade packages unless the user asks.
