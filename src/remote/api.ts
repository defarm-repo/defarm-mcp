/**
 * Cliente HTTP mínimo da API da DeFarm para o MCP REMOTO.
 *
 * Segurança (é o desenho): o servidor remoto NÃO tem credencial própria. Cada requisição MCP
 * traz a chave de API do PARCEIRO, e é ela que vai para a DeFarm. A autorização continua toda no
 * backend: o assistente de IA enxerga exatamente o que aquela chave já enxerga. A chave nunca é
 * logada nem devolvida em resposta.
 */
export interface ApiOptions {
  baseUrl: string;
  apiKey: string;
  fetchImpl?: typeof fetch | undefined;
  userAgent?: string | undefined;
}

export class DefarmApiError extends Error {
  constructor(
    readonly status: number,
    message: string,
    readonly body: unknown,
  ) {
    super(message);
    this.name = "DefarmApiError";
  }
}

export class RemoteApi {
  private readonly base: string;
  private readonly f: typeof fetch;

  constructor(private readonly opts: ApiOptions) {
    this.base = opts.baseUrl.replace(/\/+$/, "");
    this.f = opts.fetchImpl ?? fetch;
  }

  async get(path: string, query: Record<string, string | number | undefined> = {}): Promise<unknown> {
    return this.request("GET", path, query);
  }

  async post(path: string, body: unknown): Promise<unknown> {
    return this.request("POST", path, {}, body);
  }

  private async request(
    method: string,
    path: string,
    query: Record<string, string | number | undefined>,
    body?: unknown,
  ): Promise<unknown> {
    const url = new URL(this.base + path);
    for (const [k, v] of Object.entries(query)) if (v !== undefined && v !== "") url.searchParams.set(k, String(v));
    const res = await this.f(url, {
      method,
      headers: {
        "x-api-key": this.opts.apiKey,
        accept: "application/json",
        "user-agent": this.opts.userAgent ?? "defarm-mcp-remote",
        ...(body !== undefined ? { "content-type": "application/json" } : {}),
      },
      body: body !== undefined ? JSON.stringify(body) : null,
    });
    const text = await res.text();
    let parsed: unknown = text;
    try {
      parsed = text ? JSON.parse(text) : null;
    } catch {
      /* corpo não-JSON: devolve texto */
    }
    if (!res.ok) {
      const msg =
        (parsed && typeof parsed === "object" && "message" in parsed && String((parsed as { message: unknown }).message)) ||
        `HTTP ${res.status}`;
      throw new DefarmApiError(res.status, `DeFarm API ${method} ${path}: ${msg}`, parsed);
    }
    return parsed;
  }
}
