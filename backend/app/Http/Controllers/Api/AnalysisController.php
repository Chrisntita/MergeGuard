<?php

namespace App\Http\Controllers\Api;

use App\Http\Requests\AnalyzeCodeRequest;
use App\Services\AI\GeminiRateLimitException;
use App\Services\AI\GeminiReviewService;
use App\Services\Analysis\CodeAnalyzer;
use App\Services\Analysis\FindingDeduplicator;
use Illuminate\Http\JsonResponse;
use Illuminate\Support\Facades\RateLimiter;
use RuntimeException;

class AnalysisController
{
    public function __invoke(
        AnalyzeCodeRequest $request,
        CodeAnalyzer $analyzer,
        GeminiReviewService $geminiReviewService,
        FindingDeduplicator $findingDeduplicator,
    ): JsonResponse {
        $language = $request->validated('language');
        $code = $request->validated('code');
        $deterministicFindings = array_map(
            fn (array $finding): array => ['source' => 'deterministic'] + $finding,
            $analyzer->analyze($language, $code),
        );

        $aiReviewEnabled = $request->boolean('ai_review', false);
        $aiFindings = [];
        $aiStatus = 'disabled';
        $aiError = null;
        $retryAfter = null;

        if ($aiReviewEnabled) {
            $rateLimitKey = 'ai-review:'.$request->ip();

            if (RateLimiter::tooManyAttempts($rateLimitKey, 5)) {
                $retryAfter = RateLimiter::availableIn($rateLimitKey);
                $aiStatus = 'rate_limited';
                $aiError = 'AI review is temporarily rate-limited. Please try again shortly.';
            } else {
                RateLimiter::hit($rateLimitKey, 60);

                try {
                    $aiFindings = $geminiReviewService->review($language, $code);
                    $aiStatus = 'completed';
                } catch (GeminiRateLimitException $exception) {
                    $aiStatus = 'provider_rate_limited';
                    $aiError = $exception->getMessage();
                } catch (RuntimeException $exception) {
                    $aiStatus = 'unavailable';
                    $aiError = $exception->getMessage();
                } catch (\Throwable) {
                    $aiStatus = 'unavailable';
                    $aiError = 'AI review is temporarily unavailable. Please try again later.';
                }
            }
        }

        $aiFindings = $findingDeduplicator->removeDuplicates($deterministicFindings, $aiFindings);
        $combinedFindings = [...$deterministicFindings, ...$aiFindings];

        $response = [
            'language' => $language,
            'deterministic_findings' => $deterministicFindings,
            'ai_findings' => $aiFindings,
            'findings' => $combinedFindings,
            'summary' => $this->buildSummary($combinedFindings),
            'ai_review' => $aiReviewEnabled,
            'ai_status' => $aiStatus,
            'ai_error' => $aiError,
        ];

        if ($retryAfter !== null) {
            $response['retry_after'] = $retryAfter;
        }

        return response()->json($response);
    }

    /**
     * @param  array<int, array<string, mixed>>  $findings
     * @return array{
     *     total: int,
     *     by_severity: array{low: int, medium: int, high: int}
     * }
     */
    private function buildSummary(array $findings): array
    {
        $summary = [
            'total' => count($findings),
            'by_severity' => [
                'low' => 0,
                'medium' => 0,
                'high' => 0,
            ],
        ];

        foreach ($findings as $finding) {
            $severity = $finding['severity'] ?? null;

            if (is_string($severity) && isset($summary['by_severity'][$severity])) {
                $summary['by_severity'][$severity]++;
            }
        }

        return $summary;
    }
}
