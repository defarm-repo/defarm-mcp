import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { createRemoteHttpHandler } from "../src/remote/http.js";
import { REMOTE_TOOLS } from "../src/remote/tools.js";
import { searchSections } from "../src/remote/docs.js";

const KEY = "chave-secreta-do-parceiro-123";
const DFID = "DFID-BEEF-BR-2026-001372-2eed81";
const calls: { url: string; key: string | null; method: string }[] = [];

/** Fake da API da DeFarm e do portal de docs. */
const fakeFetch: typeof fetch = async (input, init) => {
  const url = String(input);
  const headers = new Headers(init?.headers);
  calls.push({ url, key: headers.get("x-api-key"), method: init?.method ?? "GET" });
  const ok = (body: unknown) => new Response(JSON.stringify(body), { status: 200, headers: { "content-type": "application/json" } });
  if (url.endsWith("/llms-full.txt")) return new Response("# DeFarm\n\n## Troca de brinco\nsubstituto=1 liga o número novo ao mesmo DFID.\n\n## Outra\nnada", { status: 200 });
  if (url.includes(`/v1/items/${DFID}`)) return ok({ item: { id: "11111111-1111-1111-1111-111111111111", dfid: DFID } });
  if (url.includes("/v1/partner/ingestions/raw")) return ok({ rows: [{ id: "r1", status: "processed", payload_text: "[{\"sisbov\":\"segredo\"}]" }] });
  if (url.includes("/v1/partner/ingestions/preview")) return ok({ dry_run: true, errors: [] });
  if (url.includes("/events/public")) return ok([{ event_type: "item_born", payload: { occurred_at: "2025-01-01" } }]);
  if (url.includes("/api/events")) return ok({ events: [{ event_type: "item_movement", payload: { gta_number: "GTA-9", origin: { cpf: "12345678900", latitude: -20.47 }, destinoLongitude: -54.6, ownerName: "Fulano" } }] });
  return ok({});
};

let server: Server;
let base: string;

async function rpc(method: string, params: unknown, key: string | null = KEY) {
  const res = await fetch(`${base}/mcp`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      accept: "application/json, text/event-stream",
      ...(key ? { "x-api-key": key } : {}),
    },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
  });
  const text = await res.text();
  return { status: res.status, text, json: text ? JSON.parse(text) : null };
}

beforeAll(async () => {
  const handler = createRemoteHttpHandler({ apiBase: "https://api.test", docsBase: "https://docs.test", fetchImpl: fakeFetch });
  server = createServer((req, res) => void handler(req, res));
  await new Promise<void>((r) => server.listen(0, r));
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});
afterAll(() => new Promise<void>((r) => server.close(() => r())));

describe("MCP remoto", () => {
  it("exige a chave do parceiro", async () => {
    const r = await rpc("tools/list", {}, null);
    expect(r.status).toBe(401);
  });

  it("só aceita POST e responde healthz", async () => {
    expect((await fetch(`${base}/mcp`)).status).toBe(405);
    expect((await fetch(`${base}/healthz`)).status).toBe(200);
  });

  it("não expõe ferramenta de escrita", async () => {
    const init = await rpc("initialize", { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "t", version: "1" } });
    expect(init.status).toBe(200);
    const r = await rpc("tools/list", {});
    const names: string[] = r.json.result.tools.map((t: { name: string }) => t.name);
    // Lista FECHADA: ferramenta nova no remoto é decisão explícita (e revisada), nunca acidente.
    expect(names.sort()).toEqual(
      [
        "defarm_animal_history",
        "defarm_get_animal",
        "defarm_ingestion_issues",
        "defarm_ingestion_status",
        "defarm_list_animals",
        "defarm_preview_ingestion",
        "defarm_recent_ingestions",
        "defarm_search_docs",
        "defarm_usage",
      ].sort(),
    );
    expect(REMOTE_TOOLS.length).toBe(8);
  });

  it("repassa a chave à API, e ela nunca volta na resposta", async () => {
    calls.length = 0;
    const r = await rpc("tools/call", { name: "defarm_get_animal", arguments: { dfid: DFID } });
    expect(r.status).toBe(200);
    expect(calls[0]!.url).toBe(`https://api.test/v1/items/${DFID}`);
    expect(calls[0]!.key).toBe(KEY);
    expect(r.text).toContain(`https://defarm.net/i/${DFID}`);
    expect(r.text).not.toContain(KEY);
  });

  it("preview é o único POST, e vai pro endpoint de preview", async () => {
    calls.length = 0;
    await rpc("tools/call", { name: "defarm_preview_ingestion", arguments: { items: [{ value_chain: "BEEF" }] } });
    expect(calls.map((c) => [c.method, new URL(c.url).pathname])).toEqual([["POST", "/v1/partner/ingestions/preview"]]);
  });

  it("não manda o conteúdo bruto dos payloads pro modelo", async () => {
    const r = await rpc("tools/call", { name: "defarm_recent_ingestions", arguments: {} });
    expect(r.text).toContain("processed");
    expect(r.text).not.toContain("segredo");
  });

  it("DFID inválido é recusado antes de chamar a API", async () => {
    calls.length = 0;
    const r = await rpc("tools/call", { name: "defarm_get_animal", arguments: { dfid: "../../admin" } });
    expect(calls.length).toBe(0);
    expect(r.text).toMatch(/DFID|invalid|Invalid/);
  });

  it("busca na documentação", async () => {
    const r = await rpc("tools/call", { name: "defarm_search_docs", arguments: { query: "troca de brinco" } });
    expect(r.text).toContain("mesmo DFID");
  });
});

describe("MCP remoto: governança", () => {
  it("Bearer só com formato de chave DeFarm (64 hex)", async () => {
    const res = await fetch(`${base}/mcp`, {
      method: "POST",
      headers: { "content-type": "application/json", authorization: "Bearer eyJhbGciOiJIUzI1NiJ9.oauth.token" },
      body: "{}",
    });
    expect(res.status).toBe(401);
  });

  it("corpo grande = 413", async () => {
    const res = await fetch(`${base}/mcp`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-api-key": KEY },
      body: JSON.stringify({ x: "a".repeat(2_100_000) }),
    });
    expect(res.status).toBe(413);
  });

  it("histórico omite dado pessoal e coordenada, mantém o resto", async () => {
    const r = await rpc("tools/call", { name: "defarm_animal_history", arguments: { dfid: DFID } });
    expect(r.text).toContain("GTA-9");
    expect(r.text).toContain("item_born");
    for (const leaked of ["12345678900", "-20.47", "-54.6", "Fulano"]) expect(r.text).not.toContain(leaked);
    expect(r.text).toContain("[omitido]");
  });
});

describe("searchSections", () => {
  it("ignora acento e ordena por relevância", () => {
    const md = "## Vacinação\nvacina vacina\n## Baixa\nvacina";
    expect(searchSections(md, "vacinacao")[0]!.title).toBe("Vacinação");
  });
});
