// Purpose types and typosquat detection.
export const POPULAR = ["react","react-dom","lodash","express","axios","chalk","commander","debug","moment","dayjs","vue","next","typescript","eslint","prettier","webpack","vite","jest","vitest","mocha","request","colors","dotenv","uuid","yargs","minimist","async","bluebird","underscore","jquery","rxjs","zod","tslib","semver","glob","rimraf","mkdirp","fs-extra","cross-env","nodemon","body-parser","cors","jsonwebtoken","bcrypt","mongoose","redis","pg","mysql","sequelize","prisma","socket.io","ws","node-fetch","cheerio","puppeteer","sharp","hono","elysia","drizzle-orm","tailwindcss","postcss","esbuild","rollup","babel-core","electron","discord.js","ethers","web3","crypto-js","coffee-script","event-stream","ua-parser-js","left-pad","svelte","astro","nuxt","fastify","koa","winston","pino","playwright","cypress","viem","openai","stripe"];

const TYPE_WORDS: Record<string, string> = {
  auth: "auth passport jwt jsonwebtoken oauth oauth2 session bcrypt bcryptjs argon2 lucia clerk supertokens oidc saml",
  web3: "ethers web3 viem wagmi solana wallet walletconnect bitcoinjs",
  crypto: "crypto cipher tweetnacl sodium libsodium elliptic noble bip39 openpgp forge jose scrypt",
  database: "prisma drizzle orm sequelize typeorm mongoose knex pg postgres mysql mysql2 redis ioredis sqlite sqlite3 mongodb kysely duckdb",
  logging: "log logger winston pino bunyan morgan debug loglevel signale",
  test: "jest vitest mocha chai playwright cypress puppeteer testing sinon ava supertest msw",
  lint: "eslint prettier biome stylelint lint oxlint husky staged",
  build: "webpack vite rollup esbuild babel swc parcel turbo tsup postcss tailwindcss typescript tsx loader plugin",
  http: "axios fetch got request undici ky superagent http https express fastify koa hono elysia ws socket io cors proxy",
  ui: "react vue svelte solid angular preact next nuxt remix astro lit ui dom components radix shadcn",
  config: "dotenv config env convict rc",
  cli: "commander yargs chalk ora inquirer cli minimist prompts picocolors kleur colors ansi",
};
const NATIVE = new Set(["sharp", "canvas", "sqlite3", "better-sqlite3", "bcrypt", "argon2", "node-gyp", "fsevents", "esbuild", "@swc/core", "duckdb"]);

export function classify(name: string, opts: { native?: boolean } = {}): string[] {
  if (!name || /[\s,]/.test(name)) return [];
  if (name.startsWith("@types/")) return ["types"];
  const toks = name.toLowerCase().split(/[\/@._-]+/).filter(Boolean);
  const t = Object.entries(TYPE_WORDS).filter(([, w]) => toks.some(x => w.split(" ").includes(x))).map(([k]) => k);
  if (opts.native || NATIVE.has(name)) t.push("native");
  return t;
}

function lev(a: string, b: string) {
  const d = Array.from({ length: a.length + 1 }, (_, i) => [i]);
  for (let j = 1; j <= b.length; j++) d[0][j] = j;
  for (let i = 1; i <= a.length; i++) for (let j = 1; j <= b.length; j++)
    d[i][j] = Math.min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1));
  return d[a.length][b.length];
}

// Real, well-known packages whose names happen to sit one letter from a popular one.
const LEGIT_NEAR = new Set(["uid", "blob", "preact", "test", "chai", "nest", "pinia", "redux", "react-is", "globby", "mitt", "vitest", "next-auth"]);

/** Returns the popular package this name seems to imitate, if any. */
export function imitates(name: string): string | undefined {
  if (POPULAR.includes(name) || LEGIT_NEAR.has(name)) return;
  const bare = name.replace(/^@[^/]+\//, "");
  const flat = (s: string) => s.replace(/[-_.]/g, "");
  return POPULAR.find(p => p.length > 3 && bare !== p && (lev(bare, p) === 1 || flat(bare) === flat(p)));
}
