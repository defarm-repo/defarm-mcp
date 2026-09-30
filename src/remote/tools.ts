/**
 * Ferramentas do MCP REMOTO: leitura do que a chave do parceiro já enxerga, mais o preview
 * (simulação que não grava). NÃO há ferramenta de escrita: ingerir de verdade continua sendo do
 * sistema do parceiro (SDK/API), não do assistente de IA. Selagem e chaves privadas ficam no MCP
 * local (stdio), nunca num servidor hospedado.
 */
import { z } from "zod";
import type { RemoteApi } from "./api.js";

export interface RemoteToolDef {
  name: string;
  description: string;
  schema: z.ZodRawShape;
  handler: (api: RemoteApi, args: Record<string, unknown>) => Promise<unknown>;
}

const dfid = z
  .string()
  .regex(/^DFID-[A-Z]{1,7}-[A-Z]{2}-\d{4}-\d{6}-[0-9a-f]{6}$/, "DFID no formato DFID-BEEF-BR-2026-001372-2eed81")
  .describe("DFID do animal, ex.: DFID-BEEF-BR-2026-001372-2eed81");

export const PUBLIC_APP = "https://defarm.net";

/**
 * Chaves de payload que não vão para o modelo (review #5): dado pessoal ou localização precisa.
 * O parceiro continua lendo tudo pela própria API; o que se evita é despejar isso num LLM de
 * terceiro por padrão. Casamento por nome, em qualquer nível do payload.
 */
const SENSITIVE_KEY = /(^|_)(cpf|cnpj|rg|documento|email|e_mail|telefone|phone|celular|lat|latitude|lon|lng|longitude|coord|coordenadas|geo|endereco|address|proprietario|owner|produtor_nome|nome_produtor|owner_name)($|_)/i;

export function redactSensitive(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(redactSensitive);
  if (value && typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      const norm = k.replace(/([a-z])([A-Z])/g, "$1_$2");
      out[k] = SENSITIVE_KEY.test(norm) ? "[omitido]" : redactSensitive(v);
    }
    return out;
  }
  return value;
}

export const REMOTE_TOOLS: RemoteToolDef[] = [
  {
    name: "defarm_list_animals",
    description:
      "Lista os animais (itens) que a chave do parceiro enxerga, com DFID, cadeia, status e identificadores. Paginado.",
    schema: {
      limit: z.number().int().min(1).max(100).optional().describe("Máximo por página (default 20)"),
      offset: z.number().int().min(0).optional().describe("Deslocamento para paginar"),
    },
    handler: (api, a) => api.get("/v1/items", { limit: (a.limit as number) ?? 20, offset: a.offset as number | undefined }),
  },
  {
    name: "defarm_get_animal",
    description:
      "Detalhe de um animal pelo DFID: identificadores, atributos e circuitos visíveis para a chave. Inclui os links da página pública (/i/) e da verificação (/v/).",
    schema: { dfid },
    handler: async (api, a) => {
      const id = a.dfid as string;
      const detail = await api.get(`/v1/items/${encodeURIComponent(id)}`);
      return { ...(detail as object), public_page: `${PUBLIC_APP}/i/${id}`, verify_page: `${PUBLIC_APP}/v/${id}` };
    },
  },
  {
    name: "defarm_animal_history",
    description:
      "Histórico do animal. Retorna os eventos PÚBLICOS (nascimento, vacinação, tratamento, baixa, reativação...) e os eventos dos circuitos que a chave alcança (inclui os de visibilidade restrita, como movimentação). Dados pessoais e localização precisa (CPF/CNPJ, contato, coordenadas, dono) vêm como \"[omitido]\"; para eles, use a API diretamente.",
    schema: { dfid, limit: z.number().int().min(1).max(100).optional() },
    handler: async (api, a) => {
      const id = a.dfid as string;
      const limit = (a.limit as number) ?? 50;
      const detail = (await api.get(`/v1/items/${encodeURIComponent(id)}`)) as { item?: { id?: string } };
      const itemId = detail?.item?.id;
      const [publicEvents, circuitEvents] = await Promise.all([
        api.get(`/api/items/${encodeURIComponent(id)}/events/public`, { limit }),
        itemId ? api.get("/api/events", { item_id: itemId, limit }) : Promise.resolve(null),
      ]);
      return { dfid: id, public_events: redactSensitive(publicEvents), circuit_events: redactSensitive(circuitEvents) };
    },
  },
  {
    name: "defarm_preview_ingestion",
    description:
      "Simula uma ingestão SEM gravar nada: mostra quais animais seriam criados ou atualizados, quais eventos seriam detectados e os erros por linha (reason_code + mensagem). Use para validar um payload PNIB antes do envio real, que é feito pelo sistema do parceiro.",
    schema: {
      items: z
        .array(z.record(z.unknown()))
        .min(1)
        .max(200)
        .describe("Linhas, ex.: {value_chain:'BEEF', numeroElementoIdentificacao:'076…', dataVacinacao:'2025-06-15', vacinaAplicada:'BRUCELOSE'}"),
    },
    handler: (api, a) => api.post("/v1/partner/ingestions/preview", { items: a.items }),
  },
  {
    name: "defarm_ingestion_status",
    description: "Status de uma ingestão assíncrona (mais de 200 linhas) pelo ingestion_id.",
    schema: { ingestion_id: z.string().uuid() },
    handler: (api, a) => api.get(`/v1/partner/ingestions/${a.ingestion_id as string}/status`),
  },
  {
    name: "defarm_ingestion_issues",
    description:
      "Problemas de ingestão em aberto do parceiro (linhas recusadas agrupadas por identificador e motivo), para corrigir na origem.",
    schema: { status: z.enum(["open", "in_review", "resolved"]).optional(), limit: z.number().int().min(1).max(100).optional() },
    handler: (api, a) => api.get("/v1/partner/ingestions/issues", { status: a.status as string | undefined, limit: (a.limit as number) ?? 50 }),
  },
  {
    name: "defarm_recent_ingestions",
    description: "Últimos envios recebidos (payloads brutos: data, status, tamanho), sem o conteúdo.",
    schema: { limit: z.number().int().min(1).max(100).optional() },
    handler: async (api, a) => {
      const r = (await api.get("/v1/partner/ingestions/raw", { limit: (a.limit as number) ?? 20 })) as { rows?: Record<string, unknown>[] };
      // Só metadados: o conteúdo bruto (payload_text) não vai para o modelo.
      return { rows: (r?.rows ?? []).map(({ payload_text: _omit, ...meta }) => meta) };
    },
  },
  {
    name: "defarm_usage",
    description: "Uso e saldo de créditos do parceiro (tokenizações totais, do dia, do mês, saldo).",
    schema: {},
    handler: (api) => api.get("/v1/partner/usage"),
  },
];
