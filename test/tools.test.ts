import { describe, expect, it } from "vitest";
import { DefarmClient, MemoryKeystore } from "@defarm/sdk";
import { TOOLS } from "../src/tools.js";

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

  it("NO tool schema accepts a credential or key-material input (auth is server config)", () => {
    const forbidden = /password|api_?key|secret|token|priv(ate)?_?key|seed|bearer/i;
    for (const t of TOOLS) {
      for (const field of Object.keys(t.schema)) {
        expect(forbidden.test(field), `${t.name}.${field} looks like a credential input`).toBe(false);
      }
    }
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
