#!/usr/bin/env node
/**
 * MCP remoto da DeFarm (Streamable HTTP, sem estado). Uso por qualquer cliente MCP que aceite
 * servidor HTTP com header: a chave de API do parceiro vai em `x-api-key` (ou
 * `Authorization: Bearer <chave>`) e é repassada à API da DeFarm em cada chamada.
 *
 *   PORT=8787 DEFARM_API_BASE=https://gateway.defarm.net DEFARM_DOCS_BASE=https://docs.defarm.net node dist/remote/http.js
 */
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { createHash } from "node:crypto";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import type { Transport } from "@modelcontextprotocol/sdk/shared/transport.js";
import { RemoteApi } from "./api.js";
import { createRemoteMcpServer } from "./server.js";

export interface RemoteHttpOptions {
  apiBase: string;
  docsBase: string;
  fetchImpl?: typeof fetch | undefined;
  /** Requisições por minuto por chave (default 120) e por IP (default 300). */
  perKeyPerMinute?: number | undefined;
  perIpPerMinute?: number | undefined;
  now?: (() => number) | undefined;
}

/** Limite por janela fixa de 1 min, em memória (uma instância). Protege a API e o servidor. */
export class RateLimiter {
  private readonly hits = new Map<string, { windowStart: number; count: number }>();
  constructor(
    private readonly limit: number,
    private readonly now: () => number = Date.now,
  ) {}

  /** null = liberado; número = segundos até a próxima janela. */
  check(key: string): number | null {
    const t = this.now();
    const w = this.hits.get(key);
    if (!w || t - w.windowStart >= 60_000) {
      this.hits.set(key, { windowStart: t, count: 1 });
      if (this.hits.size > 50_000) this.sweep(t);
      return null;
    }
    w.count += 1;
    return w.count > this.limit ? Math.max(1, Math.ceil((w.windowStart + 60_000 - t) / 1000)) : null;
  }

  private sweep(t: number): void {
    for (const [k, v] of this.hits) if (t - v.windowStart >= 60_000) this.hits.delete(k);
  }
}

function clientIp(req: IncomingMessage): string {
  const xff = req.headers["x-forwarded-for"];
  const first = (Array.isArray(xff) ? xff[0] : xff)?.split(",")[0]?.trim();
  return first || req.socket.remoteAddress || "unknown";
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
  const byKey = new RateLimiter(opts.perKeyPerMinute ?? 120, opts.now);
  const byIp = new RateLimiter(opts.perIpPerMinute ?? 300, opts.now);
  return async (req: IncomingMessage, res: ServerResponse): Promise<void> => {
    const url = new URL(req.url ?? "/", "http://localhost");
    if (url.pathname === "/healthz") return json(res, 200, { status: "ok" });
    if (url.pathname !== "/mcp") return json(res, 404, { error: "not_found" });
    const ipWait = byIp.check(clientIp(req));
    if (ipWait !== null) {
      res.setHeader("retry-after", String(ipWait));
      return json(res, 429, { error: "rate_limited", retry_after_seconds: ipWait });
    }
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
    // Pela chave (hash: a chave crua não fica nem na memória do limitador).
    const keyWait = byKey.check(createHash("sha256").update(apiKey).digest("hex"));
    if (keyWait !== null) {
      res.setHeader("retry-after", String(keyWait));
      return json(res, 429, { error: "rate_limited", retry_after_seconds: keyWait });
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
    perKeyPerMinute: process.env.MCP_RATE_PER_KEY ? Number(process.env.MCP_RATE_PER_KEY) : undefined,
    perIpPerMinute: process.env.MCP_RATE_PER_IP ? Number(process.env.MCP_RATE_PER_IP) : undefined,
  });
  createServer((req, res) => {
    handler(req, res).catch(() => {
      if (!res.headersSent) json(res, 500, { error: "internal" });
    });
  }).listen(port, () => console.error(`defarm-mcp-remote: listening on :${port} (POST /mcp)`));
}
