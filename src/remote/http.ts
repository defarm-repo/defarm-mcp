#!/usr/bin/env node
/**
 * MCP remoto da DeFarm (Streamable HTTP, sem estado). Uso por qualquer cliente MCP que aceite
 * servidor HTTP com header: a chave de API do parceiro vai em `x-api-key` (ou
 * `Authorization: Bearer <chave>`) e é repassada à API da DeFarm em cada chamada.
 *
 *   PORT=8787 DEFARM_API_BASE=https://gateway.defarm.net DEFARM_DOCS_BASE=https://docs.defarm.net node dist/remote/http.js
 */
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import type { Transport } from "@modelcontextprotocol/sdk/shared/transport.js";
import { RemoteApi } from "./api.js";
import { createRemoteMcpServer } from "./server.js";

export interface RemoteHttpOptions {
  apiBase: string;
  docsBase: string;
  fetchImpl?: typeof fetch | undefined;
}

export function extractApiKey(req: IncomingMessage): string | null {
  const x = req.headers["x-api-key"];
  if (typeof x === "string" && x.trim()) return x.trim();
  // Bearer só se tiver o formato de chave DeFarm (64 hex): um token OAuth que o cliente MCP
  // mande por conta própria não pode ser repassado à API como se fosse chave (review #5).
  const auth = req.headers["authorization"];
  if (typeof auth === "string") {
    const token = auth.replace(/^Bearer\s+/i, "").trim();
    if (/^Bearer\s+/i.test(auth) && /^[0-9a-f]{64}$/i.test(token)) return token;
  }
  return null;
}

const MAX_BODY_BYTES = 2_000_000;
class BodyTooLarge extends Error {}

async function readJson(req: IncomingMessage): Promise<unknown> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of req) {
    size += (chunk as Buffer).length;
    if (size > MAX_BODY_BYTES) throw new BodyTooLarge();
    chunks.push(chunk as Buffer);
  }
  const raw = Buffer.concat(chunks).toString("utf8");
  return raw ? JSON.parse(raw) : undefined;
}

function json(res: ServerResponse, status: number, body: unknown): void {
  res.writeHead(status, { "content-type": "application/json" });
  res.end(JSON.stringify(body));
}

export function createRemoteHttpHandler(opts: RemoteHttpOptions) {
  return async (req: IncomingMessage, res: ServerResponse): Promise<void> => {
    const url = new URL(req.url ?? "/", "http://localhost");
    if (url.pathname === "/healthz") return json(res, 200, { status: "ok" });
    if (url.pathname !== "/mcp") return json(res, 404, { error: "not_found" });
    if (req.method !== "POST") {
      // Sem estado: sem stream GET nem DELETE de sessão.
      res.setHeader("allow", "POST");
      return json(res, 405, { error: "method_not_allowed" });
    }
    const apiKey = extractApiKey(req);
    if (!apiKey) {
      return json(res, 401, {
        error: "missing_api_key",
        message: "Send your DeFarm partner API key in the x-api-key header (or Authorization: Bearer).",
      });
    }
    let body: unknown;
    try {
      body = await readJson(req);
    } catch (e) {
      if (e instanceof BodyTooLarge) return json(res, 413, { error: "payload_too_large", max_bytes: MAX_BODY_BYTES });
      return json(res, 400, { error: "invalid_json" });
    }
    const api = new RemoteApi({ baseUrl: opts.apiBase, apiKey, fetchImpl: opts.fetchImpl, userAgent: "defarm-mcp-remote/0.2.0" });
    const server = createRemoteMcpServer(api, { docsBase: opts.docsBase, fetchImpl: opts.fetchImpl });
    const transport = new StreamableHTTPServerTransport({ enableJsonResponse: true }); // sem sessionIdGenerator = sem estado
    res.on("close", () => {
      void transport.close();
      void server.close();
    });
    // O tipo do transporte diverge de Transport só sob exactOptionalPropertyTypes (onclose?).
    await server.connect(transport as unknown as Transport);
    await transport.handleRequest(req, res, body);
  };
}

const isMain = import.meta.url === `file://${process.argv[1]}`;
if (isMain) {
  const port = Number(process.env.PORT ?? 8787);
  const handler = createRemoteHttpHandler({
    apiBase: process.env.DEFARM_API_BASE ?? "https://gateway.defarm.net",
    docsBase: process.env.DEFARM_DOCS_BASE ?? "https://docs.defarm.net",
  });
  createServer((req, res) => {
    handler(req, res).catch(() => {
      if (!res.headersSent) json(res, 500, { error: "internal" });
    });
  }).listen(port, () => console.error(`defarm-mcp-remote: listening on :${port} (POST /mcp)`));
}
