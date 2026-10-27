import { afterEach, describe, expect, it, vi } from "vitest";
import { analyzeCode, getHealthStatus, getSupportedLanguages } from "./api";

describe("getHealthStatus", () => {
  afterEach(() => {
    vi.unstubAllEnvs();
    vi.unstubAllGlobals();
  });

  it("requests the health endpoint and returns its JSON response", async () => {
    vi.stubEnv("VITE_API_BASE_URL", "http://127.0.0.1:8000/api/");
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: vi.fn().mockResolvedValue({ status: "ok" }),
    });
    vi.stubGlobal("fetch", fetchMock);

    await expect(getHealthStatus()).resolves.toEqual({ status: "ok" });
    expect(fetchMock).toHaveBeenCalledWith("http://127.0.0.1:8000/api/health");
  });

  it("rejects non-OK HTTP responses", async () => {
    vi.stubEnv("VITE_API_BASE_URL", "http://127.0.0.1:8000/api");
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue({ ok: false, status: 503 }),
    );

    await expect(getHealthStatus()).rejects.toThrow(
      "The backend request failed (503).",
    );
  });

  it("loads languages using the backend response shape", async () => {
    vi.stubEnv("VITE_API_BASE_URL", "http://127.0.0.1:8000/api");
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue({
        ok: true,
        json: vi.fn().mockResolvedValue({
          languages: [{ id: "php", name: "PHP" }],
        }),
      }),
    );

    await expect(getSupportedLanguages()).resolves.toEqual([
      { id: "php", name: "PHP" },
    ]);
  });

  it("posts code for analysis and exposes backend validation messages", async () => {
    vi.stubEnv("VITE_API_BASE_URL", "http://127.0.0.1:8000/api");
    const fetchMock = vi.fn().mockResolvedValue({
      ok: false,
      status: 422,
      json: vi.fn().mockResolvedValue({
        message: "The given data was invalid.",
        errors: { code: ["The code must not exceed 100 KB."] },
      }),
    });
    vi.stubGlobal("fetch", fetchMock);

    await expect(
      analyzeCode("javascript", "console.log(1)"),
    ).rejects.toMatchObject({
      name: "ApiError",
      status: 422,
      validationErrors: ["The code must not exceed 100 KB."],
    });
    expect(fetchMock).toHaveBeenCalledWith(
      "http://127.0.0.1:8000/api/analyze",
      expect.objectContaining({
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          language: "javascript",
          code: "console.log(1)",
          ai_review: false,
        }),
      }),
    );
  });

  it("includes the AI review flag when enabled", async () => {
    vi.stubEnv("VITE_API_BASE_URL", "http://127.0.0.1:8000/api");
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: vi.fn().mockResolvedValue({
        language: "javascript",
        findings: [],
        deterministic_findings: [],
        ai_findings: [],
        summary: { total: 0, by_severity: { low: 0, medium: 0, high: 0 } },
        ai_review: true,
        ai_status: "completed",
        ai_error: null,
      }),
    });
    vi.stubGlobal("fetch", fetchMock);

    await expect(analyzeCode("javascript", "console.log(1)", true)).resolves.toMatchObject({
      ai_review: true,
      ai_status: "completed",
    });
    expect(fetchMock).toHaveBeenCalledWith(
      "http://127.0.0.1:8000/api/analyze",
      expect.objectContaining({
        body: JSON.stringify({
          language: "javascript",
          code: "console.log(1)",
          ai_review: true,
        }),
      }),
    );
  });
});
