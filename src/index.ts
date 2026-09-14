import { Client, InvalidCredentialsError } from "ldapts";
import type { PluginContext, ServerPlugin } from "@droposs/plugin-sdk";

export interface LdapConfig {
  /** LDAP URL (proto/host/port only), e.g. `ldaps://dc.example.com:636`. */
  url: string;
  /** Base DN users are authenticated under. */
  baseDn: string;
  /**
   * Bind DN template. `{username}` is replaced with the RFC 4514-escaped
   * username. When the placeholder is absent, `uid=<username>,<baseDn>` is
   * used for backwards compatibility.
   */
  bindDn: string;
}

export interface Credentials {
  username: string;
  password: string;
}

/** Minimal surface of the `ldapts` client used here, kept injectable for tests. */
export interface LdapClientLike {
  bind(dn: string, password: string): Promise<void>;
  unbind(): Promise<void>;
}

export type LdapClientFactory = (config: LdapConfig) => LdapClientLike;

const CONFIG_KEY = "ldap_config";
const DEFAULT_TIMEOUT_MS = 10_000;
const DEFAULT_CONNECT_TIMEOUT_MS = 5_000;

/** Escapes a value for inclusion in a DN per RFC 4514. */
export function escapeDnValue(value: string): string {
  return value
    .replace(/\\/g, "\\\\")
    .replace(/\0/g, "\\00")
    .replace(/([,+"<>;=#])/g, "\\$1")
    .replace(/^ /, "\\ ")
    .replace(/ $/, "\\ ");
}

/** Resolves the DN to bind as, expanding `{username}` in the configured template. */
export function resolveBindDn(config: LdapConfig, username: string): string {
  const escaped = escapeDnValue(username);
  if (config.bindDn.includes("{username}")) {
    return config.bindDn.replaceAll("{username}", escaped);
  }
  return `uid=${escaped},${config.baseDn}`;
}

export const defaultClientFactory: LdapClientFactory = (config) =>
  new Client({
    url: config.url,
    timeout: DEFAULT_TIMEOUT_MS,
    connectTimeout: DEFAULT_CONNECT_TIMEOUT_MS,
  });

function isInvalidCredentials(error: unknown): boolean {
  if (error instanceof InvalidCredentialsError) return true;
  const candidate = error as { code?: unknown; name?: unknown } | null;
  return (
    candidate?.code === 49 || candidate?.name === "InvalidCredentialsError"
  );
}

/**
 * Performs a real LDAP simple bind. Returns `false` when the directory rejects
 * the credentials and rethrows transport/server failures so callers fail
 * closed on directory outages rather than treating them as a bad password.
 */
export async function verifyCredentials(
  config: LdapConfig,
  credentials: Credentials,
  createClient: LdapClientFactory = defaultClientFactory,
): Promise<boolean> {
  const client = createClient(config);
  try {
    await client.bind(
      resolveBindDn(config, credentials.username),
      credentials.password,
    );
    return true;
  } catch (error) {
    if (isInvalidCredentials(error)) return false;
    throw error;
  } finally {
    await client.unbind().catch(() => undefined);
  }
}

/** Validates and normalizes untrusted config input. Passwords are never accepted. */
export function parseConfig(input: unknown): LdapConfig {
  const body = (input ?? {}) as Record<string, unknown>;
  const url = String(body.url ?? body.host ?? "").trim();
  const baseDn = String(body.baseDn ?? "").trim();
  const bindDn = String(body.bindDn ?? "").trim();
  if (!url || !baseDn || !bindDn) {
    throw new Error("LDAP config requires url (or host), baseDn, and bindDn");
  }
  if (!/^ldaps?:\/\//i.test(url)) {
    throw new Error("LDAP url must start with ldap:// or ldaps://");
  }
  return { url, baseDn, bindDn };
}

function publicConfig(config: LdapConfig | null) {
  return {
    configured: config !== null,
    url: config?.url,
    baseDn: config?.baseDn,
    bindDn: config?.bindDn,
  };
}

export default class LdapAuthPlugin implements ServerPlugin {
  metadata = {
    id: "drop-auth-ldap",
    name: "LDAP Auth Connector",
    version: "0.1.0",
    apiVersion: 2,
    capabilities: ["routes" as const, "storage" as const, "network" as const],
  };

  private config: LdapConfig | null = null;

  constructor(private readonly createClient?: LdapClientFactory) {}

  async init(ctx: PluginContext): Promise<void> {
    this.config = await ctx.storage.get<LdapConfig>(CONFIG_KEY);
    if (!this.config) {
      ctx.logger.warn("LDAP connector installed without a saved config");
    }

    ctx.registerRoute("GET", "/config", async () => publicConfig(this.config));

    ctx.registerRoute("POST", "/config", async (event) => {
      const body = (event as { body?: unknown }).body ?? {};
      const config = parseConfig(body);
      await ctx.storage.set(CONFIG_KEY, config);
      this.config = config;
      ctx.logger.info(`LDAP connector configured for ${config.url}`);
      return publicConfig(config);
    });

    ctx.registerRoute("POST", "/verify", async (event) => {
      const config = this.config;
      if (!config) throw new Error("LDAP connector is not configured");
      const body = (event as { body?: Partial<Credentials> }).body ?? {};
      const username = String(body.username ?? "");
      const password = String(body.password ?? "");
      if (!username || !password) return { authenticated: false };
      try {
        const authenticated = await verifyCredentials(
          config,
          { username, password },
          this.createClient,
        );
        return { authenticated };
      } catch (error) {
        ctx.logger.error(
          `LDAP bind failed for ${username}: ${(error as Error).message}`,
        );
        return { authenticated: false, unavailable: true };
      }
    });

    ctx.logger.info("LDAP auth connector initialized");
  }
}
