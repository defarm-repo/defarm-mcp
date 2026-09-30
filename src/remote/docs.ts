/**
 * Documentação para o assistente de IA, lida do portal (docs.defarm.net). Fonte única: os mesmos
 * arquivos que o site publica (spec OpenAPI do parceiro e llms.txt / llms-full.txt), sem segunda
 * base editorial.
 */
export const DOC_RESOURCES = [
  {
    name: "openapi-partner",
    uri: "defarm://docs/openapi-partner-public.yaml",
    path: "/openapi-partner-public.yaml",
    mimeType: "application/yaml",
    description: "Especificação OpenAPI da API de parceiro (/v1/partner/*): ingestão, preview, status, erros.",
  },
  {
    name: "llms",
    uri: "defarm://docs/llms.txt",
    path: "/llms.txt",
    mimeType: "text/markdown",
    description: "Índice da documentação para modelos de linguagem.",
  },
  {
    name: "llms-full",
    uri: "defarm://docs/llms-full.txt",
    path: "/llms-full.txt",
    mimeType: "text/markdown",
    description: "Documentação completa em markdown (guias, perfil PNIB, SDKs, erros).",
  },
] as const;

export async function fetchDoc(docsBase: string, path: string, fetchImpl: typeof fetch = fetch): Promise<string> {
  const res = await fetchImpl(docsBase.replace(/\/+$/, "") + path);
  if (!res.ok) return `(documento indisponível: HTTP ${res.status} em ${path})`;
  return await res.text();
}

/** Busca simples por seção ("## ..."): devolve as seções com mais ocorrências dos termos. */
export function searchSections(markdown: string, query: string, max = 5): { title: string; text: string }[] {
  const terms = query
    .toLowerCase()
    .normalize("NFD")
    .replace(/[̀-ͯ]/g, "")
    .split(/\s+/)
    .filter((t) => t.length > 1);
  if (terms.length === 0) return [];
  const sections = markdown.split(/\n(?=#{1,3} )/);
  const scored = sections
    .map((s) => {
      const hay = s.toLowerCase().normalize("NFD").replace(/[̀-ͯ]/g, "");
      const score = terms.reduce((n, t) => n + (hay.split(t).length - 1), 0);
      return { s, score };
    })
    .filter((x) => x.score > 0)
    .sort((a, b) => b.score - a.score)
    .slice(0, max);
  return scored.map(({ s }) => {
    const [first, ...rest] = s.split("\n");
    const text = rest.join("\n").trim();
    return { title: (first ?? "").replace(/^#+\s*/, ""), text: text.length > 4000 ? text.slice(0, 4000) + "\n…" : text };
  });
}
