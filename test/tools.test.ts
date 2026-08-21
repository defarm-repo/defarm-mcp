import { describe, expect, it } from "vitest";
import { z } from "zod";
import { DefarmClient, MemoryKeystore } from "@defarm/sdk";
import { TOOLS } from "../src/tools.js";

/** Collect every field name in a zod raw shape, RECURSIVELY (objects, arrays, wrappers, unions). */
function collectFieldNames(shape: z.ZodRawShape, out: string[] = []): string[] {
  for (const [key, schema] of Object.entries(shape)) {
    out.push(key);
    walkZod(schema as z.ZodTypeAny, out);
  }
  return out;
}

function walkZod(schema: z.ZodTypeAny, out: string[]): void {
  const def = (schema as { _def?: Record<string, unknown> })._def;
  if (!def) return;
  const t = def["typeName"];
  if (t === "ZodObject") {
    const shape = (def["shape"] as () => z.ZodRawShape)();
    collectFieldNames(shape, out);
  } else if (t === "ZodArray") {
    walkZod(def["type"] as z.ZodTypeAny, out);
  } else if (t === "ZodOptional" || t === "ZodNullable" || t === "ZodDefault") {
    walkZod(def["innerType"] as z.ZodTypeAny, out);
  } else if (t === "ZodEffects") {
    walkZod(def["schema"] as z.ZodTypeAny, out);
  } else if (t === "ZodRecord" || t === "ZodMap") {
    walkZod(def["valueType"] as z.ZodTypeAny, out);
  } else if (t === "ZodUnion" || t === "ZodDiscriminatedUnion") {
    for (const o of def["options"] as z.ZodTypeAny[]) walkZod(o, out);
  }
}

/**
 * The tool table is the contract: names, no-credential-inputs, and handlers that actually call
 * the SDK. Handlers run against a client with an injected fake fetch — no MCP transport needed.
 */

function tool(name: string) {
  const t = TOOLS.find((t) => t.name === name);
  if (!t) throw new Error(`tool ${name} missing`);
  return t;
}

function fakeClient(): { client: DefarmClient; calls: string[] } {
  const calls: string[] = [];
  const fetchImpl = (async (url: string, init?: RequestInit) => {
    const method = init?.method ?? "GET";
    calls.push(`${method} ${new URL(url).pathname}`);
    const respond = (body: unknown) => new Response(JSON.stringify(body), { status: 200 });
    if (url.endsWith("/auth/me")) return respond({ user_id: "u1", workspace_id: "ws-1" });
    if (url.includes("/verify/")) return respond({ dfid: "DFID-X", trusted_timestamps: [] });
    if (url.includes("/items/")) return respond({ item: { id: "uuid-1", dfid: "DFID-X" } });
    if (url.includes("/search/identifier")) return respond({ item: { dfid: "DFID-X" } });
    if (url.includes("/partner/ingestions")) return respond({ items: [{ dfid: "DFID-DEFARM-BR-2026-000001-000001" }] });
    return respond({});
  }) as unknown as typeof fetch;
  const client = new DefarmClient({
    gateway: "https://example.invalid",
    auth: { bearer: "tok", apiKey: "key" },
    keystore: new MemoryKeystore(),
    fetch: fetchImpl,
  });
  return { client, calls };
}

describe("tool table contract", () => {
  it("exposes the expected tools, by name", () => {
    const names = TOOLS.map((t) => t.name).sort();
    expect(names).toEqual(
      [
        "defarm_ensure_keys",
        "defarm_export_recipient",
        "defarm_get_item",
        "defarm_get_item_public",
        "defarm_ingest",
        "defarm_open",
        "defarm_resolve_identifier",
        "defarm_seal",
        "defarm_verify",
        "defarm_whoami",
      ].sort(),
    );
  });

  it("NO tool schema accepts a credential or key-material input — at ANY depth", () => {
    // Review finding (mcp#1): checking only top-level keys left nested objects (e.g. the
    // recipient bundle) unguarded — exactly where a field would slip in unnoticed. This walker
    // descends the zod tree; the self-test below proves it bites on nested fields.
    const forbidden = /password|api_?key|secret|token|priv(ate)?_?key|seed|bearer/i;
    for (const t of TOOLS) {
      for (const field of collectFieldNames(t.schema)) {
        expect(forbidden.test(field), `${t.name}.${field} looks like a credential input`).toBe(false);
      }
    }
  });

  it("self-test: the schema walker catches a forbidden field NESTED inside an object/array", () => {
    const evil: z.ZodRawShape = {
      bundle: z.object({ privateKey: z.string() }),
      list: z.array(z.object({ inner: z.object({ apiKey: z.string() }) })).optional(),
    };
    const names = collectFieldNames(evil);
    expect(names).toContain("privateKey");
    expect(names).toContain("apiKey");
  });

  it("whoami / verify / get_item / resolve handlers hit the right endpoints", async () => {
    const { client, calls } = fakeClient();
    await tool("defarm_whoami").handler(client, {});
    await tool("defarm_verify").handler(client, { dfid: "DFID-X" });
    await tool("defarm_get_item").handler(client, { dfid: "DFID-X" });
    await tool("defarm_resolve_identifier").handler(client, { identifierType: "SISBOV", value: "105000000000001" });
    expect(calls).toContain("GET /auth/me");
    expect(calls.some((c) => c.startsWith("GET /v1/verify/"))).toBe(true);
    expect(calls.some((c) => c.startsWith("GET /v1/items/"))).toBe(true);
    expect(calls.some((c) => c.startsWith("GET /v1/search/identifier"))).toBe(true);
  });

  it("ingest handler passes preview through as a dry-run", async () => {
    const { client, calls } = fakeClient();
    const out = (await tool("defarm_ingest").handler(client, {
      items: [{ value_chain: "DEFARM" }],
      preview: true,
    })) as { preview: boolean; dfids: string[] };
    expect(out.preview).toBe(true);
    expect(calls.some((c) => c.endsWith("/partner/ingestions/preview"))).toBe(true);
  });

  it("ensure_keys result carries NO private material", async () => {
    const { client } = fakeClient();
    // Registration endpoints answer 200 {} in the fake — enough for the shape check.
    const out = await tool("defarm_ensure_keys").handler(client, {});
    const text = JSON.stringify(out);
    expect(text).toMatch(/signingKeyId/);
    expect(text).not.toMatch(/privateKey|private_key|seed/i);
  });
});
