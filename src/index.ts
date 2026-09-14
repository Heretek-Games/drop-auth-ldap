import type { PluginContext, ServerPlugin } from "@droposs/plugin-sdk";

export type HttpFetch = (input: string | URL, init?: RequestInit) => Promise<Response>;

export interface LdapConfig {
  url: string;
  bindDn: string;
  searchBase: string;
}

export interface Credentials {
  username: string;
  password: string;
}

/** Minimal LDAP bind check against an injected fetch (kept dependency-free). */
export async function verifyCredentials(
  config: LdapConfig,
  credentials: Credentials,
  fetchFn: HttpFetch,
): Promise<boolean> {
  const url = new URL("/api/v1/client/ldap/verify", config.url);
  url.searchParams.set("bindDn", `uid=${credentials.username},${config.searchBase}`);
  const response = await fetchFn(url.toString(), {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ bindDn: config.bindDn }),
  });
  return response.ok;
}

export default class LdapAuthPlugin implements ServerPlugin {
  metadata = {
    id: "drop-auth-ldap",
    name: "LDAP Auth Connector",
    version: "0.1.0",
    apiVersion: 2,
    capabilities: ["routes" as const, "storage" as const, "network" as const],
  };

  async init(ctx: PluginContext): Promise<void> {
    const config = await ctx.storage.get<LdapConfig>("ldap_config");
    if (!config) {
      ctx.logger.warn("LDAP connector installed without a saved config");
    }

    ctx.registerRoute("GET", "/config", async () => ({
      configured: config !== null,
      url: config?.url,
      searchBase: config?.searchBase,
    }));

    ctx.registerRoute("POST", "/verify", async (event) => {
      if (!config) throw new Error("LDAP connector is not configured");
      const body = (event as { body?: Credentials }).body ?? { username: "", password: "" };
      const ok = await verifyCredentials(config, body, ctx.fetch.bind(ctx));
      return { authenticated: ok };
    });

    ctx.logger.info("LDAP auth connector initialized");
  }
}
