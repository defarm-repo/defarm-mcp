/**
 * The tool table — every DeFarm capability the agent can call, in one auditable place.
 *
 * Design rules (they ARE the security posture):
 * - **Credentials never flow through the model.** Auth (login/API key) is SERVER configuration
 *   (environment, see config.ts) — there is no login tool, no tool takes a password or key.
 * - **No tool returns private key material.** Ever. `ensure_keys` returns ids/fingerprints.
 * - **Safe defaults are the SDK's**: sealing is private, the sealer's own key is always
 *   included, the crypto suite is fixed and never exposed as a choice.
 * - Handlers are plain functions over a `DefarmClient` — unit-testable without MCP transport.
 */
import { z } from "zod";
import type { DefarmClient } from "@defarm/sdk";

export interface ToolDef {
  name: string;
  description: string;
  schema: z.ZodRawShape;
  handler: (client: DefarmClient, args: Record<string, unknown>) => Promise<unknown>;
}

const recipientBundle = z
  .object({
    workspaceId: z.string(),
    encKeyId: z.string(),
    encPubkeyB64: z.string(),
    signingPubkeyB64: z.string(),
    bindingSigB64: z.string(),
  })
  .describe(
    "A recipient bundle exported by the RECIPIENT'S own SDK/MCP (defarm_export_recipient) and " +
      "shared out of band. Public material only; the binding signature is re-verified before sealing.",
  );

export const TOOLS: ToolDef[] = [
  {
    name: "defarm_whoami",
    description: "Who the configured credentials belong to (user + workspace).",
    schema: {},
    handler: (c) => c.me(),
  },
  {
    name: "defarm_ensure_keys",
    description:
      "Generate (locally, first time only) and register this workspace's key pairs — Ed25519 for " +
      "authorship, X25519 for encryption with a signed binding. Idempotent and race-safe. Returns " +
      "ids and fingerprints ONLY; private keys stay in the local keystore and are never returned.",
    schema: {},
    handler: (c) => c.ensureKeys(),
  },
  {
    name: "defarm_export_recipient",
    description:
      "Export THIS workspace's public recipient bundle (public keys + signed binding, straight " +
      "from the server's directory listings) so someone else can seal fields addressed to it. " +
      "Share the result out of band. Contains only public material.",
    schema: {},
    handler: (c) => c.exportRecipient(),
  },
  {
    name: "defarm_ingest",
    description:
      "Partner ingestion of items/animals (requires the server to be configured with a partner " +
      "API key). Set preview=true for a dry run that validates without writing or anchoring — " +
      "recommended before real ingestion. Returns the DFIDs created.",
    schema: {
      items: z.array(z.record(z.unknown())).describe(
        "Items to ingest, e.g. {value_chain:'DEFARM', country:'BR', year:2026, sisbov:'105…(14-15 digits)', breed, sex, weight_kg, category}",
      ),
      preview: z.boolean().optional().describe("true = dry-run, nothing written"),
    },
    handler: (c, a) =>
      c.ingest(
        a.items as Record<string, unknown>[],
        a.preview !== undefined ? { preview: a.preview as boolean } : {},
      ),
  },
  {
    name: "defarm_seal",
    description:
      "Seal one field of an item: encrypt CLIENT-SIDE so only the addressed recipients can ever " +
      "read it — the DeFarm server stores an envelope it structurally cannot open. Defaults are " +
      "safe: no recipients = sealed for yourself only; your own key is always included; " +
      "visibility is private. Each recipient bundle's binding is cryptographically re-verified " +
      "before sealing — a swapped key is refused. The field must be declared sealable by DeFarm.",
    schema: {
      dfid: z.string().describe("The item's DFID"),
      fieldPath: z.string().describe("The field to seal, e.g. 'preco_venda'"),
      value: z.string().describe("The value to seal (sealed as text/plain)"),
      circuitId: z.string().describe("The circuit the sealed event is written into"),
      to: z.array(recipientBundle).optional(),
      includeSelf: z.boolean().optional().describe("Default true — you never lose access to your own data"),
      visibility: z.enum(["private", "public"]).optional().describe(
        "Default private. 'public' surfaces the ENVELOPE (commitment, never the value) on public /verify.",
      ),
    },
    handler: (c, a) =>
      c
        .seal({
          dfid: a.dfid as string,
          fieldPath: a.fieldPath as string,
          value: a.value,
          circuitId: a.circuitId as string,
          ...(a.to !== undefined ? { to: a.to as never } : {}),
          ...(a.includeSelf !== undefined ? { includeSelf: a.includeSelf as boolean } : {}),
          ...(a.visibility !== undefined ? { visibility: a.visibility as "private" | "public" } : {}),
        })
        // The full envelope is verbose and carries co-recipient ids — project what matters.
        .then((r: import("@defarm/sdk").SealResult) => ({
          dfid: r.dfid,
          fieldPath: r.fieldPath,
          commitment: r.commitment,
          recipients: r.recipients,
          clientEventId: r.clientEventId,
        })),
  },
  {
    name: "defarm_open",
    description:
      "Open a sealed field addressed to THIS workspace: fetches the envelope, unwraps and " +
      "decrypts with the LOCAL private key, verifies the commitment and re-verifies the sealer's " +
      "signature locally (you do not have to trust the server's boolean).",
    schema: {
      dfid: z.string(),
      fieldPath: z.string(),
    },
    handler: (c, a) =>
      c
        .open({ dfid: a.dfid as string, fieldPath: a.fieldPath as string })
        .then((r: import("@defarm/sdk").OpenResult) => ({
          value: r.value,
          sealer: r.sealer,
          authorshipVerified: r.authorshipVerified,
          sealerSignatureVerifiedLocally: r.sealerSignatureVerifiedLocally,
        })),
  },
  {
    name: "defarm_verify",
    description:
      "Public verification of a DFID — no account, no trust in DeFarm required. Returns the " +
      "aggregator report plus extractions (RFC3161 trusted timestamps, sealed-field commitments). " +
      "For fully independent verification use the open-source defarm-verify tooling.",
    schema: { dfid: z.string() },
    handler: (c, a) => c.verify(a.dfid as string),
  },
  {
    name: "defarm_get_item",
    description:
      "Read an item as the authenticated workspace (membership-gated: members see clear fields " +
      "raw; non-members get a uniform 404 — no existence oracle).",
    schema: { dfid: z.string() },
    handler: (c, a) => c.getItem(a.dfid as string),
  },
  {
    name: "defarm_get_item_public",
    description:
      "Read an item's PUBLIC view (skeleton + commitments, personal identifiers masked). Only " +
      "items in public circuits are served; private ones return the uniform 404.",
    schema: { dfid: z.string() },
    handler: (c, a) => c.getItemPublic(a.dfid as string),
  },
  {
    name: "defarm_resolve_identifier",
    description: "Resolve an item by a domain identifier (SISBOV, chip, …).",
    schema: {
      identifierType: z.string().describe("e.g. 'SISBOV'"),
      value: z.string(),
      circuitId: z.string().optional(),
    },
    handler: (c, a) =>
      c.resolveByIdentifier(
        a.identifierType as string,
        a.value as string,
        a.circuitId as string | undefined,
      ),
  },
];
