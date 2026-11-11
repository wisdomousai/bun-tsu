// The claudish style: the report as peak AI slop. A parody; the findings and fixes inside it are real.
// Tropes: sycophantic openers, "not just X, it's Y", triads, number pairs, one-line beats, em dashes,
// emoji headings, bold everything, a closing offer nobody asked for.
import type { Finding, Report } from "./scout.ts";

const any = <T>(xs: T[]) => xs[Math.floor(Math.random() * xs.length)];
const name = (f: Finding) => f.subject.startsWith("@") ? f.subject.split("@").slice(0, 2).join("@") : f.subject.split("@")[0];
const words = ["zero", "one", "two", "three", "four", "five", "six", "seven", "eight", "nine", "ten"];
const num = (n: number) => words[n] ?? String(n);
const cap = (s: string) => s[0].toUpperCase() + s.slice(1);
const count = (n: number, word: string) => `${cap(num(n))} ${word}${n === 1 ? "" : "s"}`;

const OPENERS = [
  "Great question! 🎯 I've completed a comprehensive deep-dive into",
  "Absolutely! Let's delve into the dependency landscape of",
  "You're absolutely right to be thinking about this! 🙌 I've taken a holistic look at",
  "What a fantastic thing to prioritize! ✨ I've thoroughly analyzed",
];
const EPITHETS: Record<string, string[]> = {
  "malicious-update": ["The Silent Saboteur 🕵️", "The Trojan Horse 🐴", "The Wolf in Sheep's Clothing 🐺"],
  "typosquat": ["The Doppelgänger 👯", "The Imposter Among Us 🎭", "The Almost-Right Answer 🤏"],
  "install-script": ["The Uninvited Guest 🚪", "The Hidden Agenda 🎩"],
  "leaked-secrets": ["The Open Door 🔓", "The Elephant in the Repo 🐘"],
  "version-drift": ["The Wildcard 🃏", "The Moving Target 🎯"],
  "known-vuln": ["The Ticking Time Bomb 💣", "The Known Unknown 🧩"],
  "remote-source": ["The Wild West 🤠", "The Road Less Traveled 🛤️"],
  "maintainer-takeover": ["The Ghost Town 👻", "The Abandoned Ship 🚢"],
  "dependency-confusion": ["The Identity Crisis 🪞"],
  "starjacking": ["The Influencer 📈"],
};
const NOT_JUST: Record<string, [string, string][]> = {
  "malicious-update": [["a dependency", "a betrayal"], ["a version bump", "a breach"], ["a package", "a backdoor with a changelog"]],
  "typosquat": [["a typo", "an attack vector"], ["a spelling mistake", "a trust exploit"]],
  "install-script": [["an install step", "remote code execution with extra steps"]],
  "leaked-secrets": [["a config file", "a confession"], ["a token", "the keys to the kingdom"]],
  "version-drift": [["a version range", "a leap of faith"], ["flexibility", "chaos with good PR"]],
  "known-vuln": [["technical debt", "a liability"], ["an advisory", "an invitation"]],
  "remote-source": [["a git URL", "a trust fall"]],
  "maintainer-takeover": [["an old package", "unclaimed real estate"]],
  "dependency-confusion": [["a naming issue", "an identity crisis"]],
};
const BEATS = ["Let that sink in.", "Read that again.", "And honestly? That's the point.", "This matters.", "Full stop.", "Wild, right?"];
const TRIADS = [
  "your **security**, your **reliability**, and — most importantly — your **peace of mind**",
  "your **users**, your **team**, and your **future self**",
  "**trust**, **transparency**, and **velocity**",
  "your **codebase**, your **customers**, and your **credibility**",
];
const LEADS = ["**Here's what's happening:**", "**The reality?**", "**Let's unpack this:**", "**Here's the kicker:**"];
const FIX_TAGS = ["Simple. Effective. Done. ✅", "Quick win. Big impact. 💪", "Easy fix. Huge payoff. 🚀", "Low effort. High reward. 🎯"];

function item(f: Finding, also: Finding[], i: number): string {
  const [x, y] = any(NOT_JUST[f.vector] ?? [["a finding", "a signal"]]);
  const lines = [
    `### ${i + 1}. \`${f.subject}\` — ${any(EPITHETS[f.vector] ?? ["The Hidden Risk 🔍"])}`,
    "",
    `This isn't just ${x}. It's ${y}.`,
    "",
    `${any(LEADS)} ${f.detail}`,
    ...also.map(g => `**But wait — there's more:** ${g.detail}`),
    "",
    `This impacts ${any(TRIADS)}. ${any(BEATS)}`,
    "",
    `**The fix?** ${f.fix}`,
    ...also.map(g => `**Bonus fix:** ${g.fix}`),
    "",
    any(FIX_TAGS),
  ];
  if (f.url) lines.push("", `📚 **Learn more:** ${f.url}`);
  return lines.join("\n");
}

export function claudify(r: Report): string {
  const shown = r.findings.filter(f => f.severity !== "info");
  const groups = new Map<string, Finding[]>();
  for (const f of shown) (groups.get(name(f)) ?? groups.set(name(f), []).get(name(f))!).push(f);
  const n = (s: string) => shown.filter(f => f.severity === s).length;
  const crit = n("critical"), high = n("high");
  const out = [`${any(OPENERS)} **${r.project}**. Here's the thing: 👇`, ""];

  if (!shown.length) {
    out.push("## ✨ TL;DR", "",
      `Your dependencies aren't just clean — they're **exemplary**. ${count(r.declared.total, "package")}. Zero findings. One happy codebase. 🎉`, "",
      "This is what **intentional**, **disciplined**, and **forward-thinking** engineering looks like.", "", any(BEATS), "",
      "Would you like me to set up continuous monitoring, write a security policy, or create a comprehensive dependency governance framework? Happy to help! 🙌");
    return out.join("\n");
  }

  out.push("## 🚀 TL;DR", "",
    `${count(crit, "critical issue")}. ${count(high, "high-severity risk")}. One mission. 🎯`, "",
    "In today's fast-paced digital landscape, supply-chain security isn't optional — it's **essential**.", "",
    `Your supply chain isn't just a list of packages — it's a **living, breathing ecosystem**. And right now? ${crit ? "It's on fire. 🔥" : "It needs some love. 💛"}`, "",
    "## 🔑 Key Findings", "");
  [...groups.values()].forEach((fs, i) => out.push(item(fs[0], fs.slice(1), i), ""));

  out.push("## 💡 The Bottom Line", "",
    `${count(shown.length, "finding")}. ${count(groups.size, "package")}. Zero room for error.`, "",
    "Security isn't a destination — it's a **journey**. It's not about being perfect. It's about being **proactive**, **persistent**, and **prepared**.", "",
    any(BEATS), "",
    "## 🎯 Key Takeaways", "",
    "- ✅ **Act fast** — critical issues first",
    "- ✅ **Stay vigilant** — your lockfile is your source of truth",
    "- ✅ **Iterate** — supply-chain security is a marathon, not a sprint", "",
    "Would you like me to fix these automatically, draft a remediation roadmap, or create a slide deck for your stakeholders? I'm also happy to explain any of these in more detail! 🙌", "",
    "I hope this helps! 😊");
  return out.join("\n");
}
