import { DefarmApiError } from "./api.js";
import { forModel, scopeErrorMessage, untrustedEnvelope } from "./tools.js";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import type { RemoteApi } from "./api.js";
import { REMOTE_TOOLS } from "./tools.js";
import { DOC_RESOURCES, fetchDoc, guidePageUrl, searchSections } from "./docs.js";

export interface RemoteServerOptions {
  docsBase: string;
  fetchImpl?: typeof fetch | undefined;
}

/** Servidor MCP remoto (somente leitura + preview) sobre a chave do parceiro. */
export function createRemoteMcpServer(api: RemoteApi, opts: RemoteServerOptions): McpServer {
  const server = new McpServer({ name: "defarm-remote", version: "0.2.0" });

  for (const tool of REMOTE_TOOLS) {
    server.tool(tool.name, tool.description, tool.schema, async (args: Record<string, unknown>) => {
      try {
        const result = await tool.handler(api, args ?? {});
        const out = tool.partnerData ? untrustedEnvelope(forModel(result)) : result;
        return { content: [{ type: "text" as const, text: JSON.stringify(out, null, 2) }] };
      } catch (e) {
        const message =
          tool.requiresScope && e instanceof DefarmApiError && e.status === 403 && /scope/i.test(e.message)
            ? scopeErrorMessage(tool)
            : e instanceof Error
              ? `${e.name}: ${e.message}`
              : String(e);
        return { content: [{ type: "text" as const, text: message }], isError: true };
      }
    });
  }

  server.tool(
    "defarm_search_docs",
    "Busca na documentação da DeFarm (guias, perfil PNIB, identificadores, eventos, erros, SDKs). Devolve as seções mais relevantes, cada uma com o link da página do guia.",
    { query: z.string().min(2).describe("Termos, ex.: 'troca de brinco', 'reason_code ambiguous_identifier'") },
    async (args: Record<string, unknown>) => {
      const full = await fetchDoc(opts.docsBase, "/llms-full.txt", opts.fetchImpl);
      const hits = searchSections(full, String(args.query ?? ""));
      const text = hits.length
        ? hits
            .map((h) => `## ${h.title}\n${h.page ? `Página: ${guidePageUrl(opts.docsBase, h.page)}\n` : ""}${h.text}`)
            .join("\n\n")
        : "Nada encontrado. Veja o recurso defarm://docs/llms.txt (índice) ou a spec OpenAPI.";
      return { content: [{ type: "text" as const, text }] };
    },
  );

  for (const doc of DOC_RESOURCES) {
    server.resource(doc.name, doc.uri, { mimeType: doc.mimeType, description: doc.description }, async (uri) => ({
      contents: [{ uri: uri.href, mimeType: doc.mimeType, text: await fetchDoc(opts.docsBase, doc.path, opts.fetchImpl) }],
    }));
  }

  return server;
}

/** Erro JSON-RPC pronto para devolver ao cliente. */
export interface JsonRpcErrorResponse {
  jsonrpc: "2.0";
  id: string | number | null;
  error: { code: number; message: string };
}

/** A partir desta versão, argumento inválido vira erro de execução (isError), não de protocolo. */
const ARGS_AS_TOOL_ERROR_FROM = "2025-11-25";

/**
 * Achado 5: na versão do protocolo negociada (até 2025-06-18), ferramenta inexistente e argumento
 * inválido são erro de protocolo -32602, não resultado com isError (o SDK embrulha os dois em
 * isError). Sem estado, a versão vem do header `mcp-protocol-version` (ausente = 2025-03-26, pela
 * especificação). Em 2025-11-25 o argumento inválido passou a ser erro de execução, e aí o
 * comportamento do SDK fica como está; ferramenta inexistente continua -32602 em todas.
 */
export function checkToolCall(
  server: McpServer,
  body: unknown,
  protocolVersion: string | undefined,
): JsonRpcErrorResponse | null {
  if (!body || typeof body !== "object" || Array.isArray(body)) return null;
  const msg = body as { method?: unknown; id?: unknown; params?: { name?: unknown; arguments?: unknown } };
  if (msg.method !== "tools/call" || msg.id === undefined) return null;
  const id = typeof msg.id === "string" || typeof msg.id === "number" ? msg.id : null;
  const name = typeof msg.params?.name === "string" ? msg.params.name : "";
  // O SDK não expõe o registro; leitura estreita, coberta por teste (quebra alto se mudar).
  const registered = (server as unknown as { _registeredTools: Record<string, { inputSchema?: z.ZodTypeAny }> })
    ._registeredTools;
  const tool = Object.prototype.hasOwnProperty.call(registered, name) ? registered[name] : undefined;
  if (!tool) return { jsonrpc: "2.0", id, error: { code: -32602, message: `Unknown tool: ${name || "(missing name)"}` } };
  if ((protocolVersion ?? "2025-03-26") >= ARGS_AS_TOOL_ERROR_FROM || !tool.inputSchema) return null;
  const parsed = tool.inputSchema.safeParse(msg.params?.arguments ?? {});
  if (parsed.success) return null;
  const detail = parsed.error.issues.map((i) => `${i.path.join(".") || "(root)"}: ${i.message}`).join("; ");
  return { jsonrpc: "2.0", id, error: { code: -32602, message: `Invalid arguments for tool ${name}: ${detail}` } };
}
