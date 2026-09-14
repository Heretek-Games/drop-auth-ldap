import test from "node:test";
import assert from "node:assert/strict";
import { InvalidCredentialsError } from "ldapts";
import { MockPluginContext } from "@droposs/plugin-sdk";
import type { RouteHandlerContext } from "@droposs/plugin-sdk";
import Plugin, {
  type LdapClientFactory,
  type LdapConfig,
  escapeDnValue,
  parseConfig,
  resolveBindDn,
  verifyCredentials,
} from "../src/index.js";

const CONFIG: LdapConfig = {
  url: "ldaps://dc.example.com:636",
  baseDn: "dc=example,dc=com",
  bindDn: "uid={username},ou=people,dc=example,dc=com",
};

function fakeClientFactory(behaviour: {
  bind?: (dn: string, password: string) => Promise<void>;
  unbind?: () => Promise<void>;
}) {
  const calls: { bound: Array<{ dn: string; password: string }>; unbinds: number } =
    { bound: [], unbinds: 0 };
  const factory: LdapClientFactory = () => ({
    async bind(dn, password) {
      calls.bound.push({ dn, password });
      if (behaviour.bind) await behaviour.bind(dn, password);
    },
    async unbind() {
      calls.unbinds += 1;
      if (behaviour.unbind) await behaviour.unbind();
    },
  });
  return { factory, calls };
}

function routeOf(ctx: MockPluginContext, method: string, pattern: string) {
  const route = ctx.routes.get(`${method} ${pattern}`);
  assert.ok(route, `expected route ${method} ${pattern}`);
  return route.handler;
}

const emptyContext: RouteHandlerContext = { params: {}, query: {} };

test("drop-auth-ldap registers config and verify routes", async () => {
  const ctx = new MockPluginContext("drop-auth-ldap", [
    "routes",
    "storage",
    "network",
  ]);
  await new Plugin().init(ctx);
  assert.ok(ctx.routes.has("GET /config"));
  assert.ok(ctx.routes.has("POST /config"));
  assert.ok(ctx.routes.has("POST /verify"));
});

test("verifyCredentials binds with the expanded user DN", async () => {
  const { factory, calls } = fakeClientFactory({});
  const ok = await verifyCredentials(
    CONFIG,
    { username: "alice", password: "s3cret" },
    factory,
  );
  assert.equal(ok, true);
  assert.deepEqual(calls.bound, [
    {
      dn: "uid=alice,ou=people,dc=example,dc=com",
      password: "s3cret",
    },
  ]);
  assert.equal(calls.unbinds, 1);
});

test("verifyCredentials escapes DN metacharacters in usernames", () => {
  assert.equal(escapeDnValue("a,b\\c+d"), "a\\,b\\\\c\\+d");
  assert.equal(
    resolveBindDn(CONFIG, "admin@example.com"),
    "uid=admin@example.com,ou=people,dc=example,dc=com",
  );
  assert.equal(
    resolveBindDn({ ...CONFIG, bindDn: "cn={username},dc=example,dc=com" }, "bob"),
    "cn=bob,dc=example,dc=com",
  );
});

test("verifyCredentials returns false on invalid credentials", async () => {
  const { factory, calls } = fakeClientFactory({
    bind: async () => {
      throw new InvalidCredentialsError();
    },
  });
  const ok = await verifyCredentials(
    CONFIG,
    { username: "alice", password: "wrong" },
    factory,
  );
  assert.equal(ok, false);
  assert.equal(calls.unbinds, 1);
});

test("verifyCredentials rethrows directory outages", async () => {
  const { factory } = fakeClientFactory({
    bind: async () => {
      throw new Error("connect ECONNREFUSED 10.0.0.1:636");
    },
  });
  await assert.rejects(
    () =>
      verifyCredentials(CONFIG, { username: "alice", password: "x" }, factory),
    /ECONNREFUSED/,
  );
});

test("POST /config persists host/baseDn/bindDn and never stores passwords", async () => {
  const ctx = new MockPluginContext("drop-auth-ldap", [
    "routes",
    "storage",
    "network",
  ]);
  const { factory, calls } = fakeClientFactory({});
  await new Plugin(factory).init(ctx);

  const logs: string[] = [];
  ctx.logger.info = (msg: string) => logs.push(msg);
  ctx.logger.warn = (msg: string) => logs.push(msg);
  ctx.logger.error = (msg: string) => logs.push(msg);
  ctx.logger.debug = (msg: string) => logs.push(msg);

  const handler = routeOf(ctx, "POST", "/config");
  const result = await handler(
    {
      body: {
        host: "ldap://ldap.internal:389",
        baseDn: "dc=example,dc=com",
        bindDn: "cn={username},ou=staff,dc=example,dc=com",
        bindPassword: "hunter2",
      },
    },
    emptyContext,
  );

  assert.deepEqual(result, {
    configured: true,
    url: "ldap://ldap.internal:389",
    baseDn: "dc=example,dc=com",
    bindDn: "cn={username},ou=staff,dc=example,dc=com",
  });
  const stored = await ctx.storage.get<LdapConfig>("ldap_config");
  assert.deepEqual(stored, {
    url: "ldap://ldap.internal:389",
    baseDn: "dc=example,dc=com",
    bindDn: "cn={username},ou=staff,dc=example,dc=com",
  });
  assert.ok(!JSON.stringify(stored).includes("hunter2"));
  assert.ok(!logs.join("\n").includes("hunter2"));

  const verify = routeOf(ctx, "POST", "/verify");
  const verified = await verify(
    { body: { username: "carol", password: "pw" } },
    emptyContext,
  );
  assert.deepEqual(verified, { authenticated: true });
  assert.equal(calls.bound[0].dn, "cn=carol,ou=staff,dc=example,dc=com");
});

test("POST /config rejects malformed input", async () => {
  const ctx = new MockPluginContext("drop-auth-ldap", [
    "routes",
    "storage",
    "network",
  ]);
  await new Plugin().init(ctx);
  const handler = routeOf(ctx, "POST", "/config");
  await assert.rejects(async () => handler({ body: { url: "ldap://x" } }, emptyContext), /requires/);
  await assert.rejects(
    async () =>
      handler(
        { body: { url: "http://x", baseDn: "dc=x", bindDn: "uid={username}" } },
        emptyContext,
      ),
    /ldap:\/\//,
  );
  assert.deepEqual(parseConfig({
    url: "ldaps://dc:636",
    baseDn: "dc=x",
    bindDn: "uid={username},dc=x",
  }), {
    url: "ldaps://dc:636",
    baseDn: "dc=x",
    bindDn: "uid={username},dc=x",
  });
});

test("POST /verify fails closed when unconfigured or when the directory is down", async () => {
  const ctx = new MockPluginContext("drop-auth-ldap", [
    "routes",
    "storage",
    "network",
  ]);
  await new Plugin().init(ctx);
  const verify = routeOf(ctx, "POST", "/verify");
  await assert.rejects(
    async () => verify({ body: { username: "a", password: "b" } }, emptyContext),
    /not configured/,
  );

  const { factory } = fakeClientFactory({
    bind: async () => {
      throw new Error("socket hang up");
    },
  });
  const ctx2 = new MockPluginContext("drop-auth-ldap", [
    "routes",
    "storage",
    "network",
  ]);
  await ctx2.storage.set("ldap_config", CONFIG);
  await new Plugin(factory).init(ctx2);
  const verify2 = routeOf(ctx2, "POST", "/verify");
  const result = await verify2(
    { body: { username: "a", password: "b" } },
    emptyContext,
  );
  assert.deepEqual(result, { authenticated: false, unavailable: true });
});
