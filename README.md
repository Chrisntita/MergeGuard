# MergeGuard

MergeGuard provides deterministic static checks and optional Gemini-powered code review for PHP, JavaScript, and TypeScript snippets. Submitted code is analyzed as text and is never executed.

## Project structure

- `frontend/` — React, TypeScript, Vite, ESLint, Prettier, and Vitest.
- `backend/` — Laravel JSON API with PostgreSQL configuration and a health endpoint.

## Prerequisites

- Node.js 20+ and npm.
- PHP 8.2+ with PDO and the PDO PostgreSQL extension enabled.
- Composer 2.
- PostgreSQL 14+.

## Frontend

From `frontend/`:

```powershell
npm install
Copy-Item .env.example .env
npm run dev
npm run build
npm run lint
npm run format:check
npm test
```

The Vite development server runs at `http://localhost:5173`. Set `VITE_API_BASE_URL` in `frontend/.env` to point the frontend at the API; see `frontend/.env.example`.

## Backend

From `backend/`:

```powershell
composer install
Copy-Item .env.example .env
php artisan key:generate
```

Create a PostgreSQL database and role matching the values in `backend/.env`, or update those values to match an existing database. Then run:

```powershell
php artisan migrate
php artisan serve
php artisan test
```

The API health endpoint is `http://localhost:8000/api/health`. CORS allows the configured `FRONTEND_URL` origin.

### Code analysis API

- `GET /api/languages` returns the supported language identifiers: `php`, `javascript`, `typescript`, and `python`.
- `POST /api/analyze` accepts JSON containing `language` and non-empty `code`. Submitted source is limited to 100 KiB (102,400 bytes); the API never executes it.
- `ai_review` is an optional boolean and defaults to `false`. Without it, only deterministic checks run. Set it to `true` to request an additional review from Google Gemini.
- The response retains `findings` and `summary`, and adds separate `deterministic_findings` and `ai_findings` arrays. Each finding has a `source` of `deterministic` or `ai`. `ai_status` is `disabled`, `completed`, `unavailable`, or `rate_limited`; `ai_error` contains a safe explanation when an enabled AI review could not be completed. AI failures do not discard completed deterministic findings.
- Findings include `rule_id`, `severity`, `title`, one-based `line`, `explanation`, and `suggested_fix`. AI responses are constrained to JSON and validated server-side; malformed findings and findings with missing or out-of-range line numbers are rejected.
- AI review requests are limited to five per client IP per minute. Deterministic-only requests are unaffected.

### Gemini setup and privacy

AI review is optional. Configure these values in `backend/.env`:

```dotenv
GEMINI_API_KEY=your-server-side-key
GEMINI_MODEL=gemini-3.1-flash-lite
GEMINI_TIMEOUT=20
```

Create a key through [Google AI Studio](https://aistudio.google.com/apikey). `GEMINI_MODEL` defaults to Google's stable, cost-efficient `gemini-3.1-flash-lite` text model (see Google's [model list](https://ai.google.dev/gemini-api/docs/models)). `GEMINI_TIMEOUT` is in seconds and is bounded to 1–30 seconds. Do not put Gemini credentials in frontend environment variables or tracked files. The backend uses Laravel's built-in HTTP client; no additional Composer package is required. Restart/reload the backend after changing its environment configuration.

When AI review is enabled, the submitted source is transmitted to Google Gemini for processing and subject to Google's data handling terms. Only submit code you are permitted to share, and remove credentials, secrets, personal data, and other sensitive material first. MergeGuard does not save snippets to a database or local storage, does not execute the source, and does not log source code or API credentials. Deterministic-only analysis does not transmit source to Google.

The deterministic rules are intentionally narrow and line-oriented. Current checks include:

- JavaScript/TypeScript: `console.log()`, `eval()`, `innerHTML` assignment with likely user-controlled values, and insecure `http://` URLs in fetch/XMLHttpRequest code.
- PHP: `var_dump()`, `eval()`, SQL built by concatenation, and `unserialize()` on request-like input.
- Python: `subprocess` calls with `shell=True` and recognizable user-controlled values (plus `os.system()`/`os.popen()` calls with such values), `eval()`/`exec()`, `print()`, SQL concatenation or interpolation with recognizable user-controlled values, and secret-like string assignments.
- Secret detection: long mixed-character string assignments to names resembling `apiKey`, `secret`, `token`, `password`, `credential`, or `privateKey`, without exposing the detected value.

These checks are narrow, line-oriented heuristics, not full parsers, AST analysis, or complete taint analysis. Python checks only inspect patterns on individual lines, recognize user-controlled values through a limited set of identifier names, and do not reliably follow assignments across lines or function calls. Multiline calls, complex f-string expressions, aliases, obfuscated code, and other equivalent patterns may be missed; code that resembles a risky pattern may still be reported. The Python `print()` check is intentionally low severity because print calls can also be legitimate application output. Comments and example placeholder strings such as `YOUR_API_KEY_HERE` are treated as non-sensitive where practical.

Example:

```powershell
Invoke-RestMethod -Method Post -Uri http://127.0.0.1:8000/api/analyze `
  -ContentType 'application/json' `
  -Body '{"language":"javascript","code":"console.log(\"debug\");"}'
```

## Formatting

Run `npm run format` from `frontend/` to format frontend source and configuration files. PHP files follow PSR-12; Laravel Pint is available through `composer format` in `backend/`.

## Tests

From `backend/`, run the PHPUnit feature suite and format the changed PHP files with Pint:

```powershell
vendor\bin\phpunit
vendor\bin\pint app\Http\Controllers\Api\AnalysisController.php app\Services\AI\GeminiReviewService.php config\services.php tests\Feature\AnalysisEndpointTest.php
```

From `frontend/`, run the frontend tests and production build:

```powershell
npm.cmd test
npm.cmd run build
```

Backend tests fake Gemini's HTTP responses and do not make external provider calls.
