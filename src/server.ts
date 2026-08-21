import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { DefarmClient } from "@defarm/sdk";
import { TOOLS } from "./tools.js";

/**
 * Wire the tool table onto an MCP server. Factory over a ready client — the transport and the
 * auth (environment) live in index.ts; this stays testable and auditable.
 */
export function createDefarmMcpServer(client: DefarmClient): McpServer {
  const server = new McpServer({ name: "defarm", version: "0.1.0" });
  for (const tool of TOOLS) {
    server.tool(tool.name, tool.description, tool.schema, async (args: Record<string, unknown>) => {
      try {
        const result = await tool.handler(client, args ?? {});
        return { content: [{ type: "text" as const, text: JSON.stringify(result, null, 2) }] };
      } catch (e) {
        // Typed SDK errors carry actionable messages (RecipientBindingError,
        // NotSealableFieldError, KeyMismatchError…) — surface them as tool errors, never crash
        // the server. The agent reads the reason and can react (e.g. "invite the recipient").
        const message = e instanceof Error ? `${e.name}: ${e.message}` : String(e);
        return { content: [{ type: "text" as const, text: message }], isError: true };
      }
    });
  }
  return server;
}
