import test from "node:test";
import assert from "node:assert/strict";
import { MockPluginContext } from "@droposs/plugin-sdk";
import Plugin from "../src/index.js";

test("drop-auth-ldap registers its routes", async () => {
  const ctx = new MockPluginContext("drop-auth-ldap", ["routes", "storage", "network"]);
  await new Plugin().init(ctx);
  assert.ok(ctx.routes.size >= 2);
});
