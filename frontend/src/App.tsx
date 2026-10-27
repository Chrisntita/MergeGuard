import { useEffect, useRef, useState, type FormEvent } from "react";
import {
  analyzeCode,
  ApiError,
  getHealthStatus,
  getSupportedLanguages,
  type AnalysisResult,
  type SupportedLanguage,
} from "./services/api";

type ConnectionStatus = "checking" | "connected" | "failed";

const initialCode = "";

export default function App() {
  const [connectionStatus, setConnectionStatus] =
    useState<ConnectionStatus>("checking");
  const [healthAttempt, setHealthAttempt] = useState(0);
  const [languages, setLanguages] = useState<SupportedLanguage[]>([]);
  const [languagesLoading, setLanguagesLoading] = useState(true);
  const [languagesError, setLanguagesError] = useState("");
  const [languagesAttempt, setLanguagesAttempt] = useState(0);
  const [language, setLanguage] = useState("");
  const [code, setCode] = useState(initialCode);
  const lineNumbersRef = useRef<HTMLPreElement>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const submissionLock = useRef(false);
  const [aiReviewEnabled, setAiReviewEnabled] = useState(false);
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [reviewErrors, setReviewErrors] = useState<string[]>([]);
  const [copyFeedback, setCopyFeedback] = useState<{
    findingId: string;
    message: string;
    copied: boolean;
  } | null>(null);

  useEffect(() => {
    let isCurrent = true;

    setConnectionStatus("checking");
    void getHealthStatus()
      .then((health) => {
        if (isCurrent) {
          setConnectionStatus(health.status === "ok" ? "connected" : "failed");
        }
      })
      .catch(() => {
        if (isCurrent) {
          setConnectionStatus("failed");
        }
      });

    return () => {
      isCurrent = false;
    };
  }, [healthAttempt]);

  useEffect(() => {
    let isCurrent = true;

    setLanguagesLoading(true);
    setLanguagesError("");
    void getSupportedLanguages()
      .then((supportedLanguages) => {
        if (isCurrent) {
          setLanguages(supportedLanguages);
          setLanguage(
            (selected) => selected || supportedLanguages[0]?.id || "",
          );
        }
      })
      .catch((error: unknown) => {
        if (isCurrent) {
          setLanguagesError(
            error instanceof Error
              ? error.message
              : "Could not load supported languages.",
          );
        }
      })
      .finally(() => {
        if (isCurrent) {
          setLanguagesLoading(false);
        }
      });

    return () => {
      isCurrent = false;
    };
  }, [languagesAttempt]);

  async function handleReviewSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (submissionLock.current) {
      return;
    }

    setReviewErrors([]);
    setResult(null);
    setCopyFeedback(null);

    if (!code.trim()) {
      setReviewErrors(["Enter a code snippet to review."]);
      return;
    }

    submissionLock.current = true;
    setIsSubmitting(true);

    try {
      setResult(await analyzeCode(language, code, aiReviewEnabled));
    } catch (error: unknown) {
      if (error instanceof ApiError && error.validationErrors.length > 0) {
        setReviewErrors(error.validationErrors);
      } else {
        setReviewErrors([
          error instanceof Error
            ? error.message
            : "Review failed. Please try again.",
        ]);
      }
    } finally {
      submissionLock.current = false;
      setIsSubmitting(false);
    }
  }

  async function handleCopyFix(findingId: string, suggestedFix: string) {
    try {
      await navigator.clipboard.writeText(suggestedFix);
      setCopyFeedback({
        findingId,
        message: "Suggested fix copied.",
        copied: true,
      });
    } catch {
      setCopyFeedback({
        findingId,
        message:
          "Could not copy. Select the suggested fix and copy it manually.",
        copied: false,
      });
    }
  }

  const healthMessage = {
    checking: "Checking backend...",
    connected: "Backend connected",
    failed: "Backend connection failed",
  }[connectionStatus];
  const lineCount = code.split("\n").length;
  const lineNumbers = Array.from(
    { length: lineCount },
    (_, index) => index + 1,
  ).join("\n");

  return (
    <main className="app-shell">
      <header className="topbar">
        <a className="brand" href="/" aria-label="MergeGuard home">
          <svg
            className="brand-mark"
            viewBox="0 0 32 32"
            fill="none"
            aria-hidden="true"
          >
            <path
              d="M16 2.75 27 6.8v8.55c0 6.1-4.45 11.35-11 13.9-6.55-2.55-11-7.8-11-13.9V6.8L16 2.75Z"
              fill="currentColor"
              fillOpacity=".13"
              stroke="currentColor"
              strokeWidth="1.5"
            />
            <path
              d="m11 13-3 3 3 3m10-6 3 3-3 3m-2-8-4 10"
              stroke="currentColor"
              strokeWidth="1.55"
              strokeLinecap="round"
              strokeLinejoin="round"
            />
          </svg>
          <span>MergeGuard</span>
          <span className="brand-product">CODE REVIEW</span>
        </a>
        <nav className="top-nav" aria-label="Main navigation">
          <a href="#editor-title">Review</a>
          <a href="#results-title">Findings</a>
        </nav>
        <div
          className={`backend-status status-${connectionStatus}`}
          role="status"
          aria-label="Backend connection"
        >
          <span className="status-indicator" aria-hidden="true" />
          <span className="backend-status-label">{healthMessage}</span>
          {connectionStatus === "failed" && (
            <button
              className="text-button"
              type="button"
              onClick={() => setHealthAttempt((attempt) => attempt + 1)}
            >
              Retry
            </button>
          )}
        </div>
      </header>

      <section className="page-intro" aria-labelledby="page-title">
        <div className="intro-mark" aria-hidden="true">
          <svg viewBox="0 0 24 24" fill="none">
            <path
              d="m8 7-5 5 5 5m8-10 5 5-5 5m-2-13-4 16"
              stroke="currentColor"
              strokeWidth="1.7"
              strokeLinecap="round"
              strokeLinejoin="round"
            />
          </svg>
        </div>
        <div>
          <p className="eyebrow">MergeGuard workspace</p>
          <h1 id="page-title">Code security review</h1>
          <p>
            Inspect a snippet for security and quality issues. Code is never
            executed.
          </p>
        </div>
      </section>

      <div className="workspace" id="analysis-workspace">
        <section className="panel editor-panel" aria-labelledby="editor-title">
          <div className="panel-heading editor-heading">
            <div>
              <h2 id="editor-title">Code input</h2>
              <p>Choose a language and paste the code you want reviewed.</p>
            </div>
            <span className="panel-step">01 / 02</span>
          </div>

          <form onSubmit={handleReviewSubmit}>
            <div className="editor-toolbar">
              <label className="field-label" htmlFor="language">
                Programming language
              </label>
              <select
                id="language"
                value={language}
                onChange={(event) => setLanguage(event.target.value)}
                disabled={
                  languagesLoading || languages.length === 0 || isSubmitting
                }
                aria-describedby={languagesError ? "language-error" : undefined}
              >
                {languagesLoading && (
                  <option value="">Loading languages...</option>
                )}
                {!languagesLoading && languages.length === 0 && (
                  <option value="">No languages available</option>
                )}
                {languages.map((supportedLanguage) => (
                  <option
                    key={supportedLanguage.id}
                    value={supportedLanguage.id}
                  >
                    {supportedLanguage.name}
                  </option>
                ))}
              </select>
              <span className="editor-toolbar-note">
                <span className="toolbar-dot" aria-hidden="true" />
                Source only · never executed
              </span>
            </div>
            {languagesError && (
              <div className="inline-error" id="language-error" role="alert">
                <span>{languagesError}</span>
                <button
                  className="text-button"
                  type="button"
                  onClick={() => setLanguagesAttempt((attempt) => attempt + 1)}
                >
                  Retry
                </button>
              </div>
            )}

            <div className="code-label-row">
              <label className="field-label code-label" htmlFor="code">
                Code snippet
              </label>
              <span className="code-limit">
                {lineCount} {lineCount === 1 ? "line" : "lines"}{" "}
                <span aria-hidden="true">·</span> Max 100 KiB
              </span>
            </div>
            <div className="code-editor">
              <div className="code-editor-bar">
                <span className="editor-language">
                  {languages.find(
                    (supportedLanguage) => supportedLanguage.id === language,
                  )?.name ?? "Source"}
                </span>
                <span className="editor-mode">Source editor</span>
              </div>
              <div className="code-editor-body">
                <pre
                  className="line-numbers"
                  aria-hidden="true"
                  ref={lineNumbersRef}
                >
                  {lineNumbers}
                </pre>
                <textarea
                  id="code"
                  name="code"
                  value={code}
                  onChange={(event) => setCode(event.target.value)}
                  onScroll={(event) => {
                    if (lineNumbersRef.current) {
                      lineNumbersRef.current.scrollTop =
                        event.currentTarget.scrollTop;
                    }
                  }}
                  placeholder={`Paste your code here...\n\nExample:\nconsole.log("debug output");`}
                  spellCheck={false}
                  wrap="off"
                  disabled={isSubmitting}
                  rows={14}
                  aria-describedby="code-help"
                />
              </div>
            </div>

            <div
              className={`ai-option ${aiReviewEnabled ? "ai-option-enabled" : ""}`}
            >
              <label className="checkbox-label" htmlFor="ai-review-toggle">
                <input
                  id="ai-review-toggle"
                  type="checkbox"
                  aria-label="Enable AI review"
                  checked={aiReviewEnabled}
                  onChange={(event) => setAiReviewEnabled(event.target.checked)}
                  disabled={isSubmitting}
                />
                <span className="ai-option-copy">
                  <strong>AI review</strong>
                  <span>Optional Gemini second opinion</span>
                </span>
              </label>
              <span className="ai-option-tag">Optional</span>
            </div>
            <p className="field-help" id="code-help">
              When enabled, code is sent to Google Gemini. Only share code
              you’re permitted to disclose, and remove secrets first.
            </p>

            <button
              className="primary-button"
              type="submit"
              disabled={
                isSubmitting ||
                languagesLoading ||
                languages.length === 0 ||
                !language
              }
            >
              <span className="button-icon" aria-hidden="true">
                {isSubmitting ? (
                  <span className="loading-spinner" />
                ) : (
                  <svg viewBox="0 0 20 20" fill="none">
                    <path
                      d="M4 10h11m-4-4 4 4-4 4"
                      stroke="currentColor"
                      strokeWidth="1.7"
                      strokeLinecap="round"
                      strokeLinejoin="round"
                    />
                  </svg>
                )}
              </span>
              {isSubmitting ? "Reviewing code..." : "Review Code"}
            </button>
          </form>
        </section>

        <section
          className="panel results-panel"
          aria-labelledby="results-title"
          aria-live="polite"
        >
          <div className="panel-heading results-heading">
            <div>
              <h2 id="results-title">Review results</h2>
              <p>Security and quality findings from your snippet.</p>
            </div>
            <span className="panel-step">02 / 02</span>
            {result && (
              <span className="result-count">
                {result.summary.total}{" "}
                {result.summary.total === 1 ? "issue" : "issues"}
              </span>
            )}
          </div>

          {isSubmitting && (
            <div className="result-state result-loading" role="status">
              <span className="state-spinner" aria-hidden="true" />
              <div>
                <strong>Review in progress</strong>
                <p>
                  {aiReviewEnabled
                    ? "Running static checks and requesting an AI review."
                    : "Running static checks on your snippet."}
                </p>
              </div>
            </div>
          )}

          {reviewErrors.length > 0 && (
            <div className="result-state result-error" role="alert">
              <span className="state-symbol" aria-hidden="true">
                !
              </span>
              <div>
                <h3>Review could not be completed</h3>
                <ul>
                  {reviewErrors.map((error, index) => (
                    <li key={`${index}-${error}`}>{error}</li>
                  ))}
                </ul>
              </div>
            </div>
          )}

          {!isSubmitting && !result && reviewErrors.length === 0 && (
            <div className="initial-state">
              <div className="initial-icon" aria-hidden="true">
                <svg viewBox="0 0 48 48" fill="none">
                  <path
                    d="M24 5.5 40 11v12.4c0 9-6.45 16.2-16 19.1-9.55-2.9-16-10.1-16-19.1V11l16-5.5Z"
                    stroke="currentColor"
                    strokeWidth="1.7"
                    strokeLinejoin="round"
                  />
                  <path
                    d="m18.5 23.5 3.7 3.7 7.6-8"
                    stroke="currentColor"
                    strokeWidth="1.9"
                    strokeLinecap="round"
                    strokeLinejoin="round"
                  />
                </svg>
              </div>
              <div className="initial-copy">
                <span className="empty-kicker">Workspace ready</span>
                <h3>Your findings will appear here</h3>
                <p>
                  Paste a code snippet, choose its language, then run a review
                  to see prioritized issues and suggested fixes.
                </p>
                <div className="initial-notes">
                  <span>
                    <span className="note-dot" aria-hidden="true" />
                    Static checks run by default
                  </span>
                  <span>
                    <span className="note-dot note-dot-ai" aria-hidden="true" />
                    AI is opt-in
                  </span>
                </div>
              </div>
            </div>
          )}

          {result && (
            <>
              <div
                className={`ai-status-banner ${result.ai_status === "unavailable" || result.ai_status === "rate_limited" || result.ai_status === "provider_rate_limited" ? "ai-status-error" : ""}`}
                role="status"
              >
                <span className="status-indicator" aria-hidden="true" />
                <span>
                  {!result.ai_review &&
                    "Deterministic-only review; AI review was not requested."}
                  {result.ai_review &&
                    result.ai_status === "completed" &&
                    "AI review completed"}
                  {result.ai_review &&
                    (result.ai_status === "rate_limited" ||
                      result.ai_status === "provider_rate_limited" ||
                      result.ai_status === "unavailable") &&
                    (result.ai_error ?? "AI review is unavailable.")}
                </span>
              </div>

              <div className="summary" aria-label="Finding summary">
                <div className="summary-total">
                  <strong>{result.summary.total}</strong>
                  <span>
                    {result.summary.total === 1 ? "finding" : "findings"}
                  </span>
                </div>
                <div
                  className="severity-counts"
                  role="list"
                  aria-label="Findings by severity"
                >
                  <span
                    className="severity-count severity-high"
                    role="listitem"
                  >
                    <span className="severity-dot" aria-hidden="true" />
                    <span>High</span>
                    <strong>{result.summary.by_severity.high}</strong>
                  </span>
                  <span
                    className="severity-count severity-medium"
                    role="listitem"
                  >
                    <span className="severity-dot" aria-hidden="true" />
                    <span>Medium</span>
                    <strong>{result.summary.by_severity.medium}</strong>
                  </span>
                  <span className="severity-count severity-low" role="listitem">
                    <span className="severity-dot" aria-hidden="true" />
                    <span>Low</span>
                    <strong>{result.summary.by_severity.low}</strong>
                  </span>
                </div>
              </div>

              {result.findings.length === 0 ? (
                <div className="result-state empty-results">
                  <span className="empty-icon" aria-hidden="true">
                    ✓
                  </span>
                  <div>
                    <h3>No findings detected</h3>
                    <p>
                      The checks completed without reporting issues for this
                      snippet.
                    </p>
                  </div>
                </div>
              ) : (
                <ol className="findings-list" aria-label="Code review findings">
                  {result.findings.map((finding, index) => {
                    const findingId = `${finding.source ?? "deterministic"}-${finding.rule_id}-${finding.line}-${index}`;
                    const feedback =
                      copyFeedback?.findingId === findingId
                        ? copyFeedback
                        : null;

                    return (
                      <li
                        className={`finding-card finding-${finding.severity}`}
                        key={findingId}
                      >
                        <div className="finding-meta">
                          <div className="finding-meta-labels">
                            <span
                              className={`severity-badge severity-${finding.severity}`}
                            >
                              <span
                                className="severity-dot"
                                aria-hidden="true"
                              />
                              {finding.severity}
                            </span>
                            <span
                              className={`source-badge source-${finding.source ?? "deterministic"}`}
                            >
                              <span className="source-dot" aria-hidden="true" />
                              {finding.source === "ai"
                                ? "AI"
                                : "Static Analysis"}
                            </span>
                          </div>
                          <div className="finding-reference">
                            <span
                              className="finding-line"
                              aria-label={`Line ${finding.line}`}
                            >
                              Line {finding.line}
                            </span>
                            <code
                              className="finding-rule"
                              aria-label={`Rule ${finding.rule_id}`}
                            >
                              {finding.rule_id}
                            </code>
                          </div>
                        </div>
                        <div className="finding-content">
                          <h3>{finding.title}</h3>
                          <p className="finding-explanation">
                            {finding.explanation}
                          </p>
                        </div>
                        {finding.suggested_fix.trim() && (
                          <div className="suggested-fix">
                            <div className="suggested-fix-heading">
                              <div>
                                <span className="fix-label">
                                  RECOMMENDATION
                                </span>
                                <strong>Suggested fix</strong>
                              </div>
                              <button
                                className="copy-fix-button"
                                type="button"
                                aria-label={`Copy suggested fix for ${finding.title}`}
                                onClick={() =>
                                  void handleCopyFix(
                                    findingId,
                                    finding.suggested_fix,
                                  )
                                }
                              >
                                {feedback
                                  ? feedback.copied
                                    ? "Copied"
                                    : "Copy failed"
                                  : "Copy fix"}
                              </button>
                            </div>
                            <p className="fix-text">{finding.suggested_fix}</p>
                            {feedback && (
                              <span
                                className={`copy-feedback ${feedback.copied ? "" : "copy-feedback-error"}`}
                                role="status"
                              >
                                {feedback.message}
                              </span>
                            )}
                          </div>
                        )}
                      </li>
                    );
                  })}
                </ol>
              )}
            </>
          )}
        </section>
      </div>
      <footer className="page-footer">
        <span>MergeGuard</span>
        <span>Deterministic analysis · No code execution</span>
      </footer>
    </main>
  );
}
