/**
 * The checks and the merge of scripts/deploy.mjs, without I/O, so that src/deploy-config.test.ts can test them.
 * wrangler.deploy.jsonc may set only the deployment values; everything else comes from wrangler.jsonc (DATA-2).
 */
import { isRecord } from "@zenith/core";
import { isOwnerPubkey, parseRelayUrl } from "../src/vars.ts";

export class DeployConfigError extends Error {}

/** The keys wrangler.deploy.jsonc may set. */
const DEPLOY_KEYS: ReadonlySet<string> = new Set(["account_id", "routes", "vars", "r2_buckets"]);
/** The Worker variables (Env in src/env.d.ts). Neither is a secret: the owner's public key and the relay URL. */
const VARS = ["OWNER_PUBKEY", "RELAY_URL"];

type Json = Record<string, unknown>;

/** Parses JSONC: JSON with comments and trailing commas, as wrangler reads it. */
export function parseJsonc(text: string): unknown {
  let out = "";
  for (let i = 0; i < text.length; i++) {
    const char = text[i];
    if (char === '"') {
      const start = i;
      for (i++; i < text.length && text[i] !== '"'; i++) if (text[i] === "\\") i++;
      out += text.slice(start, i + 1);
    } else if (char === "/" && text[i + 1] === "/") {
      while (i < text.length && text[i] !== "\n") i++;
      out += "\n";
    } else if (char === "/" && text[i + 1] === "*") {
      i = text.indexOf("*/", i + 2) + 1;
      if (i === 0) throw new DeployConfigError("unterminated comment");
    } else {
      out += char;
    }
  }
  return JSON.parse(out.replaceAll(/,(\s*[\]}])/g, "$1"));
}

function fail(message: string): never {
  throw new DeployConfigError(message);
}

/**
 * The host a route serves: a custom domain's pattern is a host name; a route pattern is `<host>/<path>`, and its host
 * may start with `*` (a wildcard subdomain), which is never the relay's host.
 */
function routeHost(route: unknown): string | undefined {
  if (typeof route === "string") return route.split("/")[0];
  if (!isRecord(route) || typeof route["pattern"] !== "string") return undefined;
  const pattern = route["pattern"];
  if (route["custom_domain"] === true) return pattern.includes("/") ? undefined : pattern;
  return pattern.split("/")[0];
}

/**
 * Checks the deployment values and returns `base` with them merged in. `main` is the Worker's entry as seen from where
 * the merged file is written. Throws {@link DeployConfigError} for anything else.
 */
export function mergeDeployConfig(base: Json, deploy: unknown, main: string): Json {
  if (!isRecord(deploy)) fail("wrangler.deploy.jsonc must be an object");
  for (const key of Object.keys(deploy)) {
    if (!DEPLOY_KEYS.has(key)) fail(`wrangler.deploy.jsonc may not set "${key}"; it belongs in wrangler.jsonc`);
  }
  const accountId = deploy["account_id"];
  if (accountId !== undefined && (typeof accountId !== "string" || !/^[0-9a-f]{32}$/.test(accountId))) {
    fail("account_id must be a Cloudflare account id (32 hex characters), or left out");
  }
  const vars = deploy["vars"];
  if (!isRecord(vars)) fail('wrangler.deploy.jsonc needs "vars" with OWNER_PUBKEY and RELAY_URL');
  if (Object.keys(vars).toSorted().join() !== VARS.join()) fail(`"vars" must set exactly ${VARS.join(" and ")}`);
  // The Worker's own checks (src/vars.ts), so that a deployed value is one the Worker accepts.
  if (!isOwnerPubkey(vars["OWNER_PUBKEY"])) {
    fail(
      "OWNER_PUBKEY must be the owner's public key as 64 lowercase hex characters (not an npub, never a secret key)",
    );
  }
  const relayUrl = parseRelayUrl(vars["RELAY_URL"]);
  if (relayUrl?.protocol !== "wss:") fail("RELAY_URL must be the wss:// URL clients connect to");
  const routes = deploy["routes"];
  if (!Array.isArray(routes) || routes.length === 0) fail('"routes" must name the relay\'s route');
  const relayHost = relayUrl.host;
  for (const route of routes as unknown[]) {
    // The host itself, not a prefix of it: `relay.example.com.other.example` is another host.
    if (routeHost(route) !== relayHost) fail(`every route must be on the host of RELAY_URL (${relayHost}) exactly`);
  }
  const baseBuckets = Array.isArray(base["r2_buckets"]) ? (base["r2_buckets"] as unknown[]).filter(isRecord) : [];
  const bindings = baseBuckets.map((bucket) => bucket["binding"]);
  const buckets = deploy["r2_buckets"];
  if (!Array.isArray(buckets) || buckets.length !== bindings.length) {
    fail(`"r2_buckets" must give a bucket_name for each binding: ${bindings.join(", ")}`);
  }
  const names = new Map<unknown, string>();
  for (const bucket of buckets as unknown[]) {
    if (!isRecord(bucket) || Object.keys(bucket).toSorted().join() !== "binding,bucket_name") {
      fail('each of "r2_buckets" has exactly "binding" and "bucket_name"');
    }
    const name = bucket["bucket_name"];
    if (!bindings.includes(bucket["binding"])) fail(`wrangler.jsonc has no R2 binding ${String(bucket["binding"])}`);
    if (typeof name !== "string" || !/^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$/.test(name)) {
      fail(`the bucket_name of ${String(bucket["binding"])} is not a bucket name`);
    }
    names.set(bucket["binding"], name);
  }
  const { $schema: _schema, ...rest } = base;
  return {
    ...rest,
    ...(accountId === undefined ? {} : { account_id: accountId }),
    main,
    routes,
    vars,
    r2_buckets: baseBuckets.map((bucket) => ({ ...bucket, bucket_name: names.get(bucket["binding"]) })),
  };
}

/**
 * Splits wrangler's options into those that choose whom wrangler authenticates as (`--profile <name>` or
 * `--profile=<name>`), which every wrangler command gets, and the rest, which only `wrangler deploy` gets. A
 * `--config` or `-c` is refused: every command reads the merged configuration.
 */
export function splitArgs(args: readonly string[]): { auth: string[]; rest: string[] } {
  const auth: string[] = [];
  const rest: string[] = [];
  for (let i = 0; i < args.length; i++) {
    const arg = args[i] ?? "";
    if (arg === "--config" || arg === "-c" || arg.startsWith("--config=")) fail("the merged configuration is used");
    if (arg.startsWith("--profile=")) auth.push(arg);
    else if (arg === "--profile" && i + 1 < args.length) auth.push(arg, args[++i] ?? "");
    else rest.push(arg);
  }
  return { auth, rest };
}
