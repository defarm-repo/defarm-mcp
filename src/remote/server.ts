import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import type { RemoteApi } from "./api.js";
import { REMOTE_TOOLS } from "./tools.js";
import { DOC_RESOURCES, fetchDoc, searchSections } from "./docs.js";

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
        return { content: [{ type: "text" as const, text: JSON.stringify(result, null, 2) }] };
      } catch (e) {
        const message = e instanceof Error ? `${e.name}: ${e.message}` : String(e);
        return { content: [{ type: "text" as const, text: message }], isError: true };
      }
    });
  }

  server.tool(
    "defarm_search_docs",
    "Busca na documentação da DeFarm (guias, perfil PNIB, identificadores, eventos, erros, SDKs). Devolve as seções mais relevantes.",
    { query: z.string().min(2).describe("Termos, ex.: 'troca de brinco', 'reason_code ambiguous_identifier'") },
    async (args: Record<string, unknown>) => {
      const full = await fetchDoc(opts.docsBase, "/llms-full.txt", opts.fetchImpl);
      const hits = searchSections(full, String(args.query ?? ""));
      const text = hits.length
        ? hits.map((h) => `## ${h.title}\n${h.text}`).join("\n\n")
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
