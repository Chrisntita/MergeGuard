import {
  cleanup,
  fireEvent,
  render,
  screen,
  within,
} from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import App from "./App";
import { ApiError } from "./services/api";

const apiMocks = vi.hoisted(() => ({
  getHealthStatus: vi.fn(),
  getSupportedLanguages: vi.fn(),
  analyzeCode: vi.fn(),
}));

vi.mock("./services/api", async (importOriginal) => ({
  ...(await importOriginal<typeof import("./services/api")>()),
  ...apiMocks,
}));

const supportedLanguages = [
  { id: "php", name: "PHP" },
  { id: "javascript", name: "JavaScript" },
  { id: "typescript", name: "TypeScript" },
];

const noFindingsResult = {
  language: "javascript",
  findings: [],
  deterministic_findings: [],
  ai_findings: [],
  summary: {
    total: 0,
    by_severity: { low: 0, medium: 0, high: 0 },
  },
  ai_review: false,
  ai_status: "disabled",
  ai_error: null,
};

const originalClipboard = Object.getOwnPropertyDescriptor(
  navigator,
  "clipboard",
);

describe("MergeGuard review workflow", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    apiMocks.getHealthStatus.mockResolvedValue({ status: "ok" });
    apiMocks.getSupportedLanguages.mockResolvedValue(supportedLanguages);
    apiMocks.analyzeCode.mockResolvedValue(noFindingsResult);
  });

  afterEach(() => {
    cleanup();
    if (originalClipboard) {
      Object.defineProperty(navigator, "clipboard", originalClipboard);
    } else {
      Reflect.deleteProperty(navigator, "clipboard");
    }
  });

  it("loads supported languages into the selector and keeps the health indicator", async () => {
    render(<App />);

    expect(
      await screen.findByRole("option", { name: "PHP" }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("option", { name: "JavaScript" }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("option", { name: "TypeScript" }),
    ).toBeInTheDocument();
    expect(await screen.findByText("Backend connected")).toBeInTheDocument();
    expect(
      screen.getByRole("link", { name: "MergeGuard home" }),
    ).toBeInTheDocument();
    expect(
      within(
        screen.getByRole("navigation", { name: "Main navigation" }),
      ).getByRole("link", { name: "Review" }),
    ).toHaveAttribute("href", "#editor-title");
  });

  it("shows the language loading state while languages are loading", () => {
    apiMocks.getSupportedLanguages.mockReturnValue(new Promise(() => {}));
    render(<App />);

    expect(
      screen.getByRole("option", { name: "Loading languages..." }),
    ).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Review Code" })).toBeDisabled();
  });

  it("keeps a line-number gutter in sync with the entered source", async () => {
    const { container } = render(<App />);

    await screen.findByRole("option", { name: "PHP" });
    fireEvent.change(screen.getByLabelText("Code snippet"), {
      target: { value: "first line\nsecond line\nthird line" },
    });

    expect(container.querySelector(".line-numbers")).toHaveTextContent("1 2 3");
  });

  it("shows concise instructions before a review without placeholder findings", () => {
    render(<App />);

    expect(
      screen.getByRole("heading", { name: "Your findings will appear here" }),
    ).toBeInTheDocument();
    expect(
      screen.getByText(
        "Paste a code snippet, choose its language, then run a review to see prioritized issues and suggested fixes.",
      ),
    ).toBeInTheDocument();
    expect(screen.queryByLabelText("Finding summary")).not.toBeInTheDocument();
    expect(
      screen.queryByRole("list", { name: "Code review findings" }),
    ).not.toBeInTheDocument();
  });

  it("submits the selected language and code and renders findings and severity totals", async () => {
    apiMocks.analyzeCode.mockResolvedValue({
      language: "javascript",
      findings: [
        {
          rule_id: "debug.console-log",
          severity: "low",
          title: "Debug logging statement",
          line: 4,
          explanation: "console.log() writes debug output.",
          suggested_fix: "Remove the debug statement.",
          source: "deterministic",
        },
      ],
      deterministic_findings: [
        {
          rule_id: "debug.console-log",
          severity: "low",
          title: "Debug logging statement",
          line: 4,
          explanation: "console.log() writes debug output.",
          suggested_fix: "Remove the debug statement.",
          source: "deterministic",
        },
      ],
      ai_findings: [],
      summary: {
        total: 1,
        by_severity: { low: 1, medium: 0, high: 0 },
      },
      ai_review: false,
      ai_status: "disabled",
      ai_error: null,
    });
    render(<App />);

    await screen.findByRole("option", { name: "PHP" });
    fireEvent.change(screen.getByLabelText("Programming language"), {
      target: { value: "javascript" },
    });
    fireEvent.change(screen.getByLabelText("Code snippet"), {
      target: { value: 'console.log("debug");' },
    });
    fireEvent.click(screen.getByRole("button", { name: "Review Code" }));

    expect(apiMocks.analyzeCode).toHaveBeenCalledWith(
      "javascript",
      'console.log("debug");',
      false,
    );
    expect(
      await screen.findByText("Debug logging statement"),
    ).toBeInTheDocument();
    expect(screen.getByText("Line 4")).toBeInTheDocument();
    expect(
      screen.getByText("console.log() writes debug output."),
    ).toBeInTheDocument();
    expect(screen.getByText("Remove the debug statement.")).toBeInTheDocument();
    expect(
      within(screen.getByLabelText("Finding summary")).getByText("1", {
        selector: ".summary-total strong",
      }),
    ).toBeInTheDocument();
    expect(screen.getByText("finding")).toBeInTheDocument();
    expect(screen.getByText("Low")).toBeInTheDocument();
  });

  it("keeps a mixed-severity finding list scannable with its source labels", async () => {
    const findings = [
      {
        rule_id: "security.sql-injection",
        severity: "high",
        title: "Potential SQL injection",
        line: 8,
        explanation: "Untrusted input reaches a database query.",
        suggested_fix: "Use a parameterized query.",
        source: "deterministic",
      },
      {
        rule_id: "ai.input-validation",
        severity: "medium",
        title: "Validate the request value",
        line: 12,
        explanation: "The request value may need validation.",
        suggested_fix: "Validate the value against the expected format.",
        source: "ai",
      },
      {
        rule_id: "debug.verbose-log",
        severity: "low",
        title: "Verbose diagnostic output",
        line: 20,
        explanation: "This statement may add noisy logs.",
        suggested_fix: "Remove or reduce the diagnostic output.",
        source: "deterministic",
      },
    ];
    apiMocks.analyzeCode.mockResolvedValue({
      ...noFindingsResult,
      findings,
      deterministic_findings: [findings[0], findings[2]],
      ai_findings: [findings[1]],
      ai_review: true,
      ai_status: "completed",
      summary: {
        total: 3,
        by_severity: { low: 1, medium: 1, high: 1 },
      },
    });
    render(<App />);

    await screen.findByRole("option", { name: "PHP" });
    fireEvent.change(screen.getByLabelText("Code snippet"), {
      target: { value: "$query = $input;" },
    });
    fireEvent.click(screen.getByLabelText("Enable AI review"));
    fireEvent.click(screen.getByRole("button", { name: "Review Code" }));

    expect(
      await screen.findByRole("list", { name: "Code review findings" }),
    ).toBeInTheDocument();
    expect(screen.getByText("Potential SQL injection")).toBeInTheDocument();
    expect(screen.getByText("Validate the request value")).toBeInTheDocument();
    expect(screen.getByText("Verbose diagnostic output")).toBeInTheDocument();
    expect(screen.getByText("security.sql-injection")).toBeInTheDocument();
    expect(screen.getByText("Line 8")).toBeInTheDocument();
    expect(screen.getAllByText("Static Analysis")).toHaveLength(2);
    expect(screen.getByText("AI")).toBeInTheDocument();
    const firstFinding = screen
      .getByText("Potential SQL injection")
      .closest(".finding-card");
    expect(firstFinding).not.toBeNull();
    expect(
      firstFinding?.querySelector(".finding-meta-labels"),
    ).toHaveTextContent(/high\s*Static Analysis/);
    expect(firstFinding?.querySelector(".finding-reference")).toHaveTextContent(
      /Line 8\s*security\.sql-injection/,
    );
    expect(
      screen.getByRole("list", { name: "Findings by severity" }),
    ).toBeInTheDocument();
    expect(
      within(screen.getByLabelText("Finding summary")).getByText("3", {
        selector: ".summary-total strong",
      }),
    ).toBeInTheDocument();
  });

  it("prevents duplicate submissions and shows a loading state", async () => {
    apiMocks.analyzeCode.mockReturnValue(new Promise(() => {}));
    render(<App />);

    await screen.findByRole("option", { name: "PHP" });
    fireEvent.change(screen.getByLabelText("Code snippet"), {
      target: { value: "const value = 1;" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Review Code" }));

    expect(
      screen.getByRole("button", { name: "Reviewing code..." }),
    ).toBeDisabled();
    expect(screen.getByText("Review in progress")).toBeInTheDocument();
    expect(
      screen.getByText("Running static checks on your snippet."),
    ).toBeInTheDocument();
  });

  it("shows an AI-specific loading message while an enabled review is running", async () => {
    apiMocks.analyzeCode.mockReturnValue(new Promise(() => {}));
    render(<App />);

    await screen.findByRole("option", { name: "PHP" });
    fireEvent.click(screen.getByLabelText("Enable AI review"));
    fireEvent.change(screen.getByLabelText("Code snippet"), {
      target: { value: "const value = 1;" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Review Code" }));

    expect(
      screen.getByText("Running static checks and requesting an AI review."),
    ).toBeInTheDocument();
  });

  it("allows AI review to be enabled and shows an AI badge when results are returned", async () => {
    apiMocks.analyzeCode.mockResolvedValue({
      language: "javascript",
      findings: [
        {
          rule_id: "ai.security-issue",
          severity: "medium",
          title: "AI security suggestion",
          line: 2,
          explanation: "This may need review.",
          suggested_fix: "Validate input.",
          source: "ai",
        },
      ],
      deterministic_findings: [],
      ai_findings: [
        {
          rule_id: "ai.security-issue",
          severity: "medium",
          title: "AI security suggestion",
          line: 2,
          explanation: "This may need review.",
          suggested_fix: "Validate input.",
          source: "ai",
        },
      ],
      summary: {
        total: 1,
        by_severity: { low: 0, medium: 1, high: 0 },
      },
      ai_review: true,
      ai_status: "completed",
      ai_error: null,
    });
    render(<App />);

    await screen.findByRole("option", { name: "PHP" });
    fireEvent.click(screen.getByLabelText("Enable AI review"));
    fireEvent.change(screen.getByLabelText("Code snippet"), {
      target: { value: "console.log('debug');" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Review Code" }));

    expect(apiMocks.analyzeCode).toHaveBeenCalledWith(
      expect.any(String),
      "console.log('debug');",
      true,
    );
    expect(await screen.findByText("AI review completed")).toBeInTheDocument();
    expect(screen.getByText("AI")).toBeInTheDocument();
  });

  it("keeps deterministic findings visible and reports an AI provider failure", async () => {
    apiMocks.analyzeCode.mockResolvedValue({
      language: "javascript",
      findings: [
        {
          rule_id: "debug.console-log",
          severity: "low",
          title: "Debug logging statement",
          line: 1,
          explanation: "Debug output remains in the snippet.",
          suggested_fix: "Remove the debug statement.",
          source: "deterministic",
        },
      ],
      deterministic_findings: [
        {
          rule_id: "debug.console-log",
          severity: "low",
          title: "Debug logging statement",
          line: 1,
          explanation: "Debug output remains in the snippet.",
          suggested_fix: "Remove the debug statement.",
          source: "deterministic",
        },
      ],
      ai_findings: [],
      summary: {
        total: 1,
        by_severity: { low: 1, medium: 0, high: 0 },
      },
      ai_review: true,
      ai_status: "unavailable",
      ai_error: "AI review is temporarily unavailable. Please try again later.",
    });
    render(<App />);

    await screen.findByRole("option", { name: "PHP" });
    fireEvent.click(screen.getByLabelText("Enable AI review"));
    fireEvent.change(screen.getByLabelText("Code snippet"), {
      target: { value: "console.log('private');" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Review Code" }));

    expect(
      await screen.findByText(
        "AI review is temporarily unavailable. Please try again later.",
      ),
    ).toBeInTheDocument();
    expect(screen.getByText("Debug logging statement")).toBeInTheDocument();
    expect(screen.getByText("Static Analysis")).toBeInTheDocument();
  });

  it("copies a finding's suggested fix and announces success", async () => {
    const writeText = vi.fn().mockResolvedValue(undefined);
    Object.defineProperty(navigator, "clipboard", {
      configurable: true,
      value: { writeText },
    });
    const finding = {
      rule_id: "debug.console-log",
      severity: "low",
      title: "Debug logging statement",
      line: 1,
      explanation: "Debug output remains in the snippet.",
      suggested_fix: "Remove the debug statement.",
      source: "deterministic",
    };
    apiMocks.analyzeCode.mockResolvedValue({
      ...noFindingsResult,
      findings: [finding],
      deterministic_findings: [finding],
      summary: {
        total: 1,
        by_severity: { low: 1, medium: 0, high: 0 },
      },
    });
    render(<App />);

    await screen.findByRole("option", { name: "PHP" });
    fireEvent.change(screen.getByLabelText("Code snippet"), {
      target: { value: "console.log('debug');" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Review Code" }));
    fireEvent.click(
      await screen.findByRole("button", {
        name: "Copy suggested fix for Debug logging statement",
      }),
    );

    expect(writeText).toHaveBeenCalledWith("Remove the debug statement.");
    expect(
      await screen.findByText("Suggested fix copied."),
    ).toBeInTheDocument();
  });

  it("explains when the browser cannot copy a suggested fix", async () => {
    const writeText = vi.fn().mockRejectedValue(new Error("Clipboard blocked"));
    Object.defineProperty(navigator, "clipboard", {
      configurable: true,
      value: { writeText },
    });
    const finding = {
      rule_id: "review.manual-check",
      severity: "medium",
      title: "Validate user input",
      line: 2,
      explanation: "Input should be checked before use.",
      suggested_fix: "Validate the input before using it.",
      source: "ai",
    };
    apiMocks.analyzeCode.mockResolvedValue({
      ...noFindingsResult,
      findings: [finding],
      ai_findings: [finding],
      ai_review: true,
      ai_status: "completed",
      summary: {
        total: 1,
        by_severity: { low: 0, medium: 1, high: 0 },
      },
    });
    render(<App />);

    await screen.findByRole("option", { name: "PHP" });
    fireEvent.change(screen.getByLabelText("Code snippet"), {
      target: { value: "const input = source;" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Review Code" }));
    fireEvent.click(
      await screen.findByRole("button", {
        name: "Copy suggested fix for Validate user input",
      }),
    );

    expect(
      await screen.findByText(
        "Could not copy. Select the suggested fix and copy it manually.",
      ),
    ).toBeInTheDocument();
  });

  it("does not show a copy action when a finding has no suggested fix", async () => {
    const finding = {
      rule_id: "review.manual-check",
      severity: "low",
      title: "Manual review recommended",
      line: 1,
      explanation: "Review this code path.",
      suggested_fix: "  ",
      source: "ai",
    };
    apiMocks.analyzeCode.mockResolvedValue({
      ...noFindingsResult,
      findings: [finding],
      ai_findings: [finding],
      ai_review: true,
      ai_status: "completed",
      summary: {
        total: 1,
        by_severity: { low: 1, medium: 0, high: 0 },
      },
    });
    render(<App />);

    await screen.findByRole("option", { name: "PHP" });
    fireEvent.change(screen.getByLabelText("Code snippet"), {
      target: { value: "const value = 1;" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Review Code" }));

    expect(
      await screen.findByText("Manual review recommended"),
    ).toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: /Copy suggested fix/ }),
    ).toBeNull();
    expect(screen.queryByText("Suggested fix")).toBeNull();
  });

  it("shows a provider rate-limit status separately from local throttling", async () => {
    apiMocks.analyzeCode.mockResolvedValue({
      ...noFindingsResult,
      ai_review: true,
      ai_status: "provider_rate_limited",
      ai_error:
        "AI review is temporarily rate-limited. Please try again in a moment.",
    });
    render(<App />);

    await screen.findByRole("option", { name: "PHP" });
    fireEvent.click(screen.getByLabelText("Enable AI review"));
    fireEvent.change(screen.getByLabelText("Code snippet"), {
      target: { value: "const value = 1;" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Review Code" }));

    expect(
      await screen.findByText(
        "AI review is temporarily rate-limited. Please try again in a moment.",
      ),
    ).toBeInTheDocument();
  });

  it("labels deterministic-only results when AI review was not requested", async () => {
    render(<App />);

    await screen.findByRole("option", { name: "PHP" });
    fireEvent.change(screen.getByLabelText("Code snippet"), {
      target: { value: "const value = 1;" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Review Code" }));

    expect(
      await screen.findByText(
        "Deterministic-only review; AI review was not requested.",
      ),
    ).toBeInTheDocument();
  });

  it("renders an empty-result message with zero severity counts", async () => {
    render(<App />);

    await screen.findByRole("option", { name: "PHP" });
    fireEvent.change(screen.getByLabelText("Code snippet"), {
      target: { value: "const value = 1;" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Review Code" }));

    expect(
      await screen.findByRole("heading", { name: "No findings detected" }),
    ).toBeInTheDocument();
    expect(
      screen.getByText(
        "The checks completed without reporting issues for this snippet.",
      ),
    ).toBeInTheDocument();
    expect(
      within(screen.getByLabelText("Finding summary")).getByText("0", {
        selector: ".summary-total strong",
      }),
    ).toBeInTheDocument();
    expect(screen.getByText("High")).toBeInTheDocument();
    expect(screen.getByText("Medium")).toBeInTheDocument();
    expect(screen.getByText("Low")).toBeInTheDocument();
  });

  it("shows backend validation errors", async () => {
    apiMocks.analyzeCode.mockRejectedValue(
      new ApiError("The given data was invalid.", 422, [
        "The code must not exceed 100 KB.",
      ]),
    );
    render(<App />);

    await screen.findByRole("option", { name: "PHP" });
    fireEvent.change(screen.getByLabelText("Code snippet"), {
      target: { value: "const value = 1;" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Review Code" }));

    expect(
      await screen.findByRole("heading", {
        name: "Review could not be completed",
      }),
    ).toBeInTheDocument();
    expect(screen.getByRole("alert")).toHaveTextContent(
      "The code must not exceed 100 KB.",
    );
  });

  it("shows a language-loading error and allows retrying", async () => {
    apiMocks.getSupportedLanguages
      .mockRejectedValueOnce(new Error("Backend unavailable"))
      .mockResolvedValueOnce(supportedLanguages);
    render(<App />);

    expect(await screen.findByText("Backend unavailable")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Retry" }));

    expect(
      await screen.findByRole("option", { name: "PHP" }),
    ).toBeInTheDocument();
  });

  it("asks for code locally instead of submitting an empty snippet", async () => {
    render(<App />);

    await screen.findByRole("option", { name: "PHP" });
    fireEvent.click(screen.getByRole("button", { name: "Review Code" }));

    expect(
      await screen.findByText("Enter a code snippet to review."),
    ).toBeInTheDocument();
    expect(apiMocks.analyzeCode).not.toHaveBeenCalled();
  });
});
