#!/usr/bin/env node
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { clientFromEnv } from "./config.js";
import { createDefarmMcpServer } from "./server.js";

const client = await clientFromEnv();
const server = createDefarmMcpServer(client);
await server.connect(new StdioServerTransport());
// stdio transport: logs go to stderr, NEVER stdout (stdout is the protocol channel).
console.error("defarm-mcp: ready (stdio)");
