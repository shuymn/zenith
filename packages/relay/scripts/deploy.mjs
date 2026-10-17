// Deploys the relay with the deployment values that stay out of the repository.
//
// wrangler.jsonc holds the bindings, the cron and the migrations. wrangler.deploy.jsonc (gitignored; copy
// wrangler.deploy.example.jsonc) holds the route, the backup bucket's name, OWNER_PUBKEY and RELAY_URL. This script
// checks the deployment file, merges it into wrangler.jsonc, writes the result under .wrangler/ (gitignored) and runs
// `wrangler deploy --config` on it. Arguments are passed to wrangler, for example `--dry-run`.
//
// Usage: pnpm --filter @zenith/relay run deploy [--dry-run]. Without --dry-run it first lists the lock rules of each
// bucket (docs/operations.md) and stops when a bucket does not exist.
import { spawnSync } from "node:child_process";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join, relative } from "node:path";
import { fileURLToPath } from "node:url";
import { DeployConfigError, mergeDeployConfig, parseJsonc, splitArgs } from "./deploy-config.ts";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const BASE = join(root, "wrangler.jsonc");
const DEPLOY = join(root, "wrangler.deploy.jsonc");
const OUT_DIR = join(root, ".wrangler", "deploy-config");
const OUT = join(OUT_DIR, "wrangler.json");

function fail(message) {
  console.error(`deploy: ${message}`);
  process.exit(1);
}

function read(path) {
  try {
    return parseJsonc(readFileSync(path, "utf8"));
  } catch (error) {
    if (error?.code === "ENOENT") fail(`${relative(root, path)} is missing; copy wrangler.deploy.example.jsonc`);
    fail(`${relative(root, path)} is not valid JSONC`);
  }
  return undefined;
}

const base = read(BASE);
let merged;
try {
  merged = mergeDeployConfig(base, read(DEPLOY), relative(OUT_DIR, join(root, base.main)));
} catch (error) {
  if (error instanceof DeployConfigError) fail(error.message);
  throw error;
}
mkdirSync(OUT_DIR, { recursive: true });
writeFileSync(OUT, `${JSON.stringify(merged, null, 2)}\n`);

// `pnpm run deploy -- --dry-run` passes the `--` on; wrangler would take every argument after it as a positional and
// deploy for real, so it is dropped.
const args = process.argv.slice(2).filter((arg, index) => !(index === 0 && arg === "--"));
if (args.includes("--")) fail("pass wrangler's options without a `--` between them");
// Every wrangler command reads the merged configuration (its account_id) and authenticates the same way.
let split;
try {
  split = splitArgs(args);
} catch (error) {
  if (error instanceof DeployConfigError) fail(error.message);
  throw error;
}
const common = ["--config", OUT, ...split.auth];
if (!split.rest.includes("--dry-run")) {
  // DATA-5: the bucket and its lock exist before the first deployment; wrangler would otherwise create the bucket
  // without a lock. `lock list` fails for a bucket that does not exist.
  for (const bucket of merged.r2_buckets) {
    const lock = spawnSync("wrangler", ["r2", "bucket", "lock", "list", bucket.bucket_name, ...common], {
      cwd: root,
      stdio: "inherit",
    });
    if (lock.status !== 0) fail(`the bucket of ${bucket.binding} must exist, with its lock, before deploying`);
  }
}
const result = spawnSync("wrangler", ["deploy", ...common, ...split.rest], { cwd: root, stdio: "inherit" });
process.exit(result.status ?? 1);
