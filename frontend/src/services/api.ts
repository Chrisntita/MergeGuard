export interface HealthStatus {
  status: string;
}

export interface SupportedLanguage {
  id: string;
  name: string;
}

export type FindingSeverity = "low" | "medium" | "high";

export type FindingSource = "deterministic" | "ai";

export interface Finding {
  rule_id: string;
  severity: FindingSeverity;
  title: string;
  line: number;
  explanation: string;
  suggested_fix: string;
  source?: FindingSource;
}

export interface AnalysisResult {
  language: string;
  findings: Finding[];
  deterministic_findings: Finding[];
  ai_findings: Finding[];
  summary: {
    total: number;
    by_severity: Record<FindingSeverity, number>;
  };
  ai_review: boolean;
  ai_status:
    | "disabled"
    | "completed"
    | "unavailable"
    | "rate_limited"
    | "provider_rate_limited";
  ai_error?: string | null;
}

export class ApiError extends Error {
  constructor(
    message: string,
    public readonly status?: number,
    public readonly validationErrors: string[] = [],
  ) {
    super(message);
    this.name = "ApiError";
  }
}

function getApiBaseUrl(): string {
  const configuredUrl = import.meta.env.VITE_API_BASE_URL;

  if (!configuredUrl) {
    throw new ApiError(
      "API URL is not configured. Set VITE_API_BASE_URL and restart the frontend.",
    );
  }

  return configuredUrl.replace(/\/+$/, "");
}

async function request<T>(path: string, options?: RequestInit): Promise<T> {
  const url = `${getApiBaseUrl()}${path}`;
  let response: Response;

  try {
    response = options ? await fetch(url, options) : await fetch(url);
  } catch {
    throw new ApiError(
      "Could not reach the backend. Check the connection and try again.",
    );
  }

  let payload: unknown;

  try {
    payload = await response.json();
  } catch {
    if (response.ok) {
      throw new ApiError(
        "The backend returned an invalid response.",
        response.status,
      );
    }
  }

  if (!response.ok) {
    const body =
      typeof payload === "object" && payload !== null
        ? (payload as Record<string, unknown>)
        : {};
    const validationErrors =
      typeof body.errors === "object" && body.errors !== null
        ? Object.values(body.errors)
            .flatMap((errors) => (Array.isArray(errors) ? errors : [errors]))
            .filter((error): error is string => typeof error === "string")
        : [];
    const message =
      typeof body.message === "string"
        ? body.message
        : `The backend request failed (${response.status}).`;

    throw new ApiError(message, response.status, validationErrors);
  }

  return payload as T;
}

export function getHealthStatus(): Promise<HealthStatus> {
  return request<HealthStatus>("/health");
}

export async function getSupportedLanguages(): Promise<SupportedLanguage[]> {
  const result = await request<{ languages: SupportedLanguage[] }>(
    "/languages",
  );
  return result.languages;
}

export function analyzeCode(
  language: string,
  code: string,
  aiReview = false,
): Promise<AnalysisResult> {
  return request<AnalysisResult>("/analyze", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ language, code, ai_review: aiReview }),
  });
}
