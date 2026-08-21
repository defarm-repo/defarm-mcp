import { DefarmClient, FileKeystore } from "@defarm/sdk";

/**
 * Auth and environment are SERVER configuration — the agent never sees or supplies a
 * credential. Whoever runs the server decides which identity it acts as.
 *
 *   DEFARM_GATEWAY   (required)  gateway base URL — ask DeFarm for your test-environment host
 *   DEFARM_EMAIL     (optional)  workspace login (with DEFARM_PASSWORD) — enables the
 *                                authenticated tools (keys, seal, open, get_item, whoami)
 *   DEFARM_PASSWORD  (optional)
 *   DEFARM_API_KEY   (optional)  partner key — enables defarm_ingest
 *   DEFARM_KEYSTORE  (optional)  path of the private-key file (default ~/.defarm/keys.json)
 *   DEFARM_NETWORK   (optional)  'testnet' (default) | 'public'
 */
export async function clientFromEnv(): Promise<DefarmClient> {
  const gateway = process.env.DEFARM_GATEWAY;
  if (!gateway) {
    throw new Error(
      "DEFARM_GATEWAY is required — set it in the MCP server config (env). " +
        "Ask the DeFarm team for your test-environment host; production is an explicit choice.",
    );
  }
  const network = process.env.DEFARM_NETWORK === "public" ? "public" : "testnet";
  const client = new DefarmClient({
    gateway,
    network,
    ...(process.env.DEFARM_API_KEY ? { auth: { apiKey: process.env.DEFARM_API_KEY } } : {}),
    ...(process.env.DEFARM_KEYSTORE
      ? { keystore: new FileKeystore(process.env.DEFARM_KEYSTORE) }
      : {}),
  });
  const email = process.env.DEFARM_EMAIL;
  const password = process.env.DEFARM_PASSWORD;
  if (email && password) {
    await client.login(email, password);
  }
  return client;
}
