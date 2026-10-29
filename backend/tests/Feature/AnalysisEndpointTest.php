<?php

namespace Tests\Feature;

use App\Http\Requests\AnalyzeCodeRequest;
use App\Services\Analysis\FindingDeduplicator;
use Illuminate\Http\Client\ConnectionException;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\RateLimiter;
use Illuminate\Testing\TestResponse;
use Monolog\Handler\TestHandler;
use Monolog\Logger;
use Tests\TestCase;

class AnalysisEndpointTest extends TestCase
{
    public function test_languages_endpoint_lists_only_supported_languages(): void
    {
        $this->getJson('/api/languages')
            ->assertOk()
            ->assertExactJson([
                'languages' => [
                    ['id' => 'php', 'name' => 'PHP'],
                    ['id' => 'javascript', 'name' => 'JavaScript'],
                    ['id' => 'typescript', 'name' => 'TypeScript'],
                    ['id' => 'python', 'name' => 'Python'],
                ],
            ]);
    }

    public function test_analysis_returns_the_documented_response_shape(): void
    {
        $this->postJson('/api/analyze', [
            'language' => 'javascript',
            'code' => 'const value = 1;',
        ])
            ->assertOk()
            ->assertExactJson([
                'language' => 'javascript',
                'deterministic_findings' => [],
                'ai_findings' => [],
                'findings' => [],
                'summary' => [
                    'total' => 0,
                    'by_severity' => [
                        'low' => 0,
                        'medium' => 0,
                        'high' => 0,
                    ],
                ],
                'ai_review' => false,
                'ai_status' => 'disabled',
                'ai_error' => null,
            ]);
    }

    public function test_javascript_console_log_is_reported_at_the_correct_line(): void
    {
        $response = $this->postJson('/api/analyze', [
            'language' => 'javascript',
            'code' => "const value = 1;\n\nconsole.log(value);",
        ])->assertOk();

        $response->assertJsonPath('findings.0.rule_id', 'debug.console-log');
        $response->assertJsonPath('findings.0.severity', 'low');
        $response->assertJsonPath('findings.0.line', 3);
        $response->assertJsonPath('findings.0.source', 'deterministic');
        $response->assertJsonPath('deterministic_findings.0.source', 'deterministic');
        $response->assertJsonPath('summary.total', 1);
        $response->assertJsonPath('summary.by_severity.low', 1);
        $response->assertJsonStructure([
            'language',
            'findings' => [[
                'rule_id',
                'severity',
                'title',
                'line',
                'explanation',
                'suggested_fix',
            ]],
            'summary' => [
                'total',
                'by_severity' => ['low', 'medium', 'high'],
            ],
        ]);
    }

    public function test_source_whitespace_is_preserved_for_correct_line_numbers(): void
    {
        $this->postJson('/api/analyze', [
            'language' => 'javascript',
            'code' => "\nconsole.log('debug');",
        ])
            ->assertOk()
            ->assertJsonPath('findings.0.line', 2);
    }

    public function test_typescript_console_log_is_reported(): void
    {
        $this->postJson('/api/analyze', [
            'language' => 'typescript',
            'code' => 'console.log("debug");',
        ])
            ->assertOk()
            ->assertJsonPath('findings.0.rule_id', 'debug.console-log');
    }

    public function test_php_var_dump_is_reported_at_the_correct_line(): void
    {
        $this->postJson('/api/analyze', [
            'language' => 'php',
            'code' => "<?php\n\nvar_dump(\$value);",
        ])
            ->assertOk()
            ->assertJsonPath('findings.0.rule_id', 'debug.var-dump')
            ->assertJsonPath('findings.0.line', 3);
    }

    public function test_python_shell_execution_with_potentially_untrusted_input_is_reported(): void
    {
        $response = $this->postJson('/api/analyze', [
            'language' => 'python',
            'code' => implode("\n", [
                '# subprocess.run(user_input, shell=True)',
                'example = "subprocess.run(user_input, shell=True)"',
                'subprocess.run(user_input, shell=True)',
                'os.system(user_input)',
            ]),
        ])
            ->assertOk()
            ->assertJsonCount(2, 'findings');

        foreach ([0 => 3, 1 => 4] as $index => $line) {
            $response->assertJsonPath("findings.{$index}.rule_id", 'security.shell-execution')
                ->assertJsonPath("findings.{$index}.severity", 'high')
                ->assertJsonPath("findings.{$index}.line", $line)
                ->assertJsonPath("findings.{$index}.source", 'deterministic');
        }
    }

    public function test_python_shell_execution_ignores_fixed_commands_and_disabled_shell(): void
    {
        $this->postJson('/api/analyze', [
            'language' => 'python',
            'code' => implode("\n", [
                'subprocess.run("ls", shell=True)',
                'subprocess.run(user_input, shell=False)',
                'os.system("echo fixed")',
                'message = "os.system(user_input)"',
            ]),
        ])
            ->assertOk()
            ->assertJsonCount(0, 'findings');
    }

    public function test_python_eval_and_exec_are_reported_at_their_lines(): void
    {
        $response = $this->postJson('/api/analyze', [
            'language' => 'python',
            'code' => implode("\n", [
                '# eval(user_input)',
                'example = "exec(payload)"',
                'eval(user_input)',
                'exec(payload)',
            ]),
        ])
            ->assertOk()
            ->assertJsonCount(2, 'findings');

        foreach ([0 => 3, 1 => 4] as $index => $line) {
            $response->assertJsonPath("findings.{$index}.rule_id", 'security.eval-python')
                ->assertJsonPath("findings.{$index}.severity", 'high')
                ->assertJsonPath("findings.{$index}.line", $line)
                ->assertJsonPath("findings.{$index}.source", 'deterministic');
        }
    }

    public function test_python_dynamic_execution_ignores_comments_strings_and_attributes(): void
    {
        $this->postJson('/api/analyze', [
            'language' => 'python',
            'code' => implode("\n", [
                '# exec(user_input)',
                'example = "eval(user_input)"',
                'doc = """',
                'eval(user_input)',
                '"""',
                'evaluator.eval(user_input)',
                'evaluate(user_input)',
            ]),
        ])
            ->assertOk()
            ->assertJsonCount(0, 'findings');
    }

    public function test_python_hard_coded_secret_is_reported_without_returning_its_value(): void
    {
        $secret = 'Ab1_'.str_repeat('xY7z', 7);
        $response = $this->postJson('/api/analyze', [
            'language' => 'python',
            'code' => "# API_TOKEN = '{$secret}'\nAPI_TOKEN = '{$secret}'",
        ])
            ->assertOk()
            ->assertJsonPath('findings.0.rule_id', 'security.hardcoded-secret')
            ->assertJsonPath('findings.0.severity', 'high')
            ->assertJsonPath('findings.0.line', 2)
            ->assertJsonPath('findings.0.source', 'deterministic');

        $this->assertStringNotContainsString($secret, $response->getContent());
    }

    public function test_python_secret_detection_ignores_placeholders_strings_and_comments(): void
    {
        $secret = 'Ab1_'.str_repeat('xY7z', 7);
        $this->postJson('/api/analyze', [
            'language' => 'python',
            'code' => implode("\n", [
                'api_key = "YOUR_API_KEY_HERE"',
                'message = "api_key = \''.$secret.'\'"',
                '# api_key = "'.$secret.'"',
                'ordinary_value = "'.$secret.'"',
                'sample = """',
                'API_KEY = "'.$secret.'"',
                '"""',
            ]),
        ])
            ->assertOk()
            ->assertJsonCount(0, 'findings');
    }

    public function test_python_print_is_reported_as_low_severity_debug_output(): void
    {
        $this->postJson('/api/analyze', [
            'language' => 'python',
            'code' => implode("\n", [
                '# print(payload)',
                'example = "print(payload)"',
                'print(payload)',
            ]),
        ])
            ->assertOk()
            ->assertJsonPath('findings.0.rule_id', 'debug.python-print')
            ->assertJsonPath('findings.0.severity', 'low')
            ->assertJsonPath('findings.0.line', 3)
            ->assertJsonPath('findings.0.source', 'deterministic');
    }

    public function test_python_print_detection_ignores_comments_strings_and_other_methods(): void
    {
        $this->postJson('/api/analyze', [
            'language' => 'python',
            'code' => implode("\n", [
                '# print(payload)',
                'message = "print(payload)"',
                'doc = """',
                'print(payload)',
                '"""',
                'printer(payload)',
                'output.print(payload)',
            ]),
        ])
            ->assertOk()
            ->assertJsonCount(0, 'findings');
    }

    public function test_python_sql_construction_with_untrusted_values_is_reported(): void
    {
        $response = $this->postJson('/api/analyze', [
            'language' => 'python',
            'code' => implode("\n", [
                '# query = "SELECT * FROM users " + user_input',
                'query = "SELECT * FROM users WHERE id = " + user_input',
                'query = f"SELECT * FROM users WHERE id = {user_id}"',
                'query = "SELECT * FROM users WHERE id = %s" % user_input',
            ]),
        ])
            ->assertOk()
            ->assertJsonCount(3, 'findings');

        foreach ([0 => 2, 1 => 3, 2 => 4] as $index => $line) {
            $response->assertJsonPath("findings.{$index}.rule_id", 'security.sql-concatenation')
                ->assertJsonPath("findings.{$index}.severity", 'high')
                ->assertJsonPath("findings.{$index}.line", $line)
                ->assertJsonPath("findings.{$index}.source", 'deterministic');
        }
    }

    public function test_python_sql_detection_ignores_parameterized_queries_comments_and_strings(): void
    {
        $this->postJson('/api/analyze', [
            'language' => 'python',
            'code' => implode("\n", [
                '# query = "SELECT * FROM users " + user_input',
                'example = "query = \'SELECT * FROM users \' + user_input"',
                'cursor.execute("SELECT * FROM users WHERE id = %s", (user_input,))',
                'query = "SELECT * FROM users WHERE id = %s"',
            ]),
        ])
            ->assertOk()
            ->assertJsonCount(0, 'findings');
    }

    public function test_secret_like_assignment_is_reported_without_returning_the_secret(): void
    {
        $secret = 'Ab1_'.str_repeat('xY7z', 7);

        $response = $this->postJson('/api/analyze', [
            'language' => 'javascript',
            'code' => "const apiKey = '{$secret}';",
        ])
            ->assertOk()
            ->assertJsonPath('findings.0.rule_id', 'security.hardcoded-secret')
            ->assertJsonPath('findings.0.severity', 'high')
            ->assertJsonPath('summary.by_severity.high', 1);

        $this->assertStringNotContainsString($secret, $response->getContent());
    }

    public function test_ordinary_string_is_not_flagged_as_a_secret(): void
    {
        $this->postJson('/api/analyze', [
            'language' => 'javascript',
            'code' => 'const apiKey = "development-key-for-local-test";',
        ])
            ->assertOk()
            ->assertJsonCount(0, 'findings');
    }

    public function test_javascript_eval_is_reported(): void
    {
        $response = $this->postJson('/api/analyze', [
            'language' => 'javascript',
            'code' => "const payload = userInput;\nconst result = eval(payload);",
        ])->assertOk();

        $response->assertJsonPath('findings.0.rule_id', 'security.eval-javascript')
            ->assertJsonPath('findings.0.line', 2)
            ->assertJsonPath('findings.0.severity', 'high');
    }

    public function test_javascript_innerhtml_assignment_is_reported(): void
    {
        $this->postJson('/api/analyze', [
            'language' => 'javascript',
            'code' => 'container.innerHTML = userInput;',
        ])
            ->assertOk()
            ->assertJsonPath('findings.0.rule_id', 'security.innerhtml-assignment')
            ->assertJsonPath('findings.0.severity', 'high');
    }

    public function test_insecure_http_url_is_reported(): void
    {
        $this->postJson('/api/analyze', [
            'language' => 'javascript',
            'code' => "fetch('http://api.example.com/v1');",
        ])
            ->assertOk()
            ->assertJsonPath('findings.0.rule_id', 'security.insecure-http-url')
            ->assertJsonPath('findings.0.severity', 'medium');
    }

    public function test_code_like_strings_and_comments_do_not_trigger_http_or_inner_html_rules(): void
    {
        $code = implode("\n", [
            'const example = "fetch(\'http://api.example.com\')";',
            'const text = "container.innerHTML = userInput";',
            'const safe = true; // fetch(\'http://api.example.com\')',
            'const alsoSafe = true; // container.innerHTML = userInput',
            '// fetch(\'http://api.example.com\')',
            '// container.innerHTML = userInput',
        ]);

        $this->postJson('/api/analyze', [
            'language' => 'javascript',
            'code' => $code,
        ])
            ->assertOk()
            ->assertJsonCount(0, 'findings');
    }

    public function test_executable_http_and_inner_html_patterns_are_still_reported(): void
    {
        $this->postJson('/api/analyze', [
            'language' => 'javascript',
            'code' => implode("\n", [
                'fetch(\'http://api.example.com\');',
                'container.innerHTML = userInput;',
            ]),
        ])
            ->assertOk()
            ->assertJsonCount(2, 'findings')
            ->assertJsonPath('findings.0.rule_id', 'security.insecure-http-url')
            ->assertJsonPath('findings.0.line', 1)
            ->assertJsonPath('findings.1.rule_id', 'security.innerhtml-assignment')
            ->assertJsonPath('findings.1.line', 2);
    }

    public function test_console_error_is_not_flagged_as_console_log(): void
    {
        $this->postJson('/api/analyze', [
            'language' => 'javascript',
            'code' => 'console.error("warn");',
        ])
            ->assertOk()
            ->assertJsonCount(0, 'findings');
    }

    public function test_harmless_string_containing_eval_is_not_flagged(): void
    {
        $this->postJson('/api/analyze', [
            'language' => 'javascript',
            'code' => 'const label = "Please evaluate this string manually";',
        ])
            ->assertOk()
            ->assertJsonCount(0, 'findings');
    }

    public function test_php_eval_is_reported(): void
    {
        $this->postJson('/api/analyze', [
            'language' => 'php',
            'code' => "\$code = \$_POST[\"code\"];\n\$compiled = eval(\$code);",
        ])
            ->assertOk()
            ->assertJsonPath('findings.0.rule_id', 'security.eval-php')
            ->assertJsonPath('findings.0.line', 2);
    }

    public function test_php_sql_concatenation_is_reported(): void
    {
        $this->postJson('/api/analyze', [
            'language' => 'php',
            'code' => '$query = "SELECT * FROM users WHERE id = " . $userId;',
        ])
            ->assertOk()
            ->assertJsonPath('findings.0.rule_id', 'security.sql-concatenation')
            ->assertJsonPath('findings.0.line', 1);
    }

    public function test_php_request_input_interpolated_into_sql_is_reported_without_ai_review(): void
    {
        $response = $this->postJson('/api/analyze', [
            'language' => 'php',
            'code' => implode("\n", [
                '<?php',
                "\$id = \$_GET['id'];",
                '$sql = "SELECT * FROM users WHERE id = \'$id\'";',
                '$result = mysqli_query($conn, $sql);',
            ]),
        ])
            ->assertOk()
            ->assertJsonPath('ai_review', false)
            ->assertJsonPath('ai_status', 'disabled')
            ->assertJsonCount(0, 'ai_findings')
            ->assertJsonPath('deterministic_findings.0.rule_id', 'security.sql-concatenation')
            ->assertJsonPath('deterministic_findings.0.severity', 'high')
            ->assertJsonPath('deterministic_findings.0.line', 3)
            ->assertJsonPath('deterministic_findings.0.source', 'deterministic')
            ->assertJsonPath('findings.0.rule_id', 'security.sql-concatenation')
            ->assertJsonPath('summary.by_severity.high', 1);

        $this->assertSame(1, $response->json('summary.total'));
    }

    public function test_php_prepared_statement_with_request_input_is_not_flagged_as_sql_concatenation(): void
    {
        $this->postJson('/api/analyze', [
            'language' => 'php',
            'code' => implode("\n", [
                '<?php',
                "\$id = \$_GET['id'];",
                '$stmt = mysqli_prepare($conn, "SELECT * FROM users WHERE id = ?");',
                'mysqli_stmt_bind_param($stmt, "s", $id);',
                'mysqli_stmt_execute($stmt);',
            ]),
        ])
            ->assertOk()
            ->assertJsonCount(0, 'findings');
    }

    public function test_parameterized_sql_query_is_not_flagged(): void
    {
        $this->postJson('/api/analyze', [
            'language' => 'php',
            'code' => '$query = "SELECT * FROM users WHERE id = ?";',
        ])
            ->assertOk()
            ->assertJsonCount(0, 'findings');
    }

    public function test_php_unserialize_of_untrusted_data_is_reported(): void
    {
        $this->postJson('/api/analyze', [
            'language' => 'php',
            'code' => '$data = unserialize($_POST["payload"]);',
        ])
            ->assertOk()
            ->assertJsonPath('findings.0.rule_id', 'security.unserialize-untrusted');
    }

    public function test_placeholder_secret_value_is_not_flagged(): void
    {
        $this->postJson('/api/analyze', [
            'language' => 'javascript',
            'code' => 'const apiKey = "YOUR_API_KEY_HERE";',
        ])
            ->assertOk()
            ->assertJsonCount(0, 'findings');
    }

    public function test_summary_counts_match_returned_findings(): void
    {
        $response = $this->postJson('/api/analyze', [
            'language' => 'javascript',
            'code' => "console.log('debug');\nfetch('http://api.example.com');\nconst apiKey = 'Ab1_".str_repeat('xY7z', 7)."';",
        ]);

        $response->assertOk();

        $data = $response->json();
        $this->assertSame(count($data['findings']), $data['summary']['total']);
        $this->assertSame(
            array_sum($data['summary']['by_severity']),
            $data['summary']['total'],
        );
    }

    public function test_rule_ids_are_stable_and_severities_are_valid(): void
    {
        $response = $this->postJson('/api/analyze', [
            'language' => 'javascript',
            'code' => "console.log('debug');\nconst apiKey = 'Ab1_".str_repeat('xY7z', 7)."';\nfetch('http://api.example.com');",
        ])->assertOk();

        $findings = $response->json('findings');
        $this->assertNotEmpty($findings);

        foreach ($findings as $finding) {
            $this->assertMatchesRegularExpression('/^[a-z0-9.-]+$/', $finding['rule_id']);
            $this->assertContains($finding['severity'], ['low', 'medium', 'high']);
        }
    }

    public function test_ai_review_is_disabled_by_default_and_does_not_call_gemini(): void
    {
        Http::fake();
        RateLimiter::clear('ai-review:127.0.0.1');

        $this->postJson('/api/analyze', [
            'language' => 'javascript',
            'code' => 'console.log("debug");',
        ])
            ->assertOk()
            ->assertJsonPath('ai_review', false)
            ->assertJsonPath('ai_status', 'disabled')
            ->assertJsonPath('ai_findings', []);

        Http::assertSentCount(0);
    }

    public function test_ai_review_enabled_calls_gemini_and_returns_valid_findings(): void
    {
        config()->set('services.gemini.key', 'test-key');

        Http::fake([
            '*' => Http::response([
                'candidates' => [[
                    'content' => ['parts' => [[
                        'text' => '{"findings":[{"rule_id":"security.input-validation","severity":"medium","title":"Potential security issue","line":1,"explanation":"This may need attention.","suggested_fix":"Validate and sanitize input."}]}',
                    ]]],
                ]],
            ]),
        ]);

        RateLimiter::clear('ai-review:127.0.0.1');

        $response = $this->withServerVariables(['REMOTE_ADDR' => '127.0.0.1'])
            ->postJson('/api/analyze', [
                'language' => 'javascript',
                'code' => 'const value = userInput;',
                'ai_review' => true,
            ])
            ->assertOk();

        $response->assertJsonPath('ai_review', true)
            ->assertJsonPath('ai_status', 'completed')
            ->assertJsonPath('ai_findings.0.rule_id', 'security.input-validation')
            ->assertJsonPath('ai_findings.0.severity', 'medium')
            ->assertJsonPath('ai_findings.0.title', 'Potential security issue')
            ->assertJsonPath('ai_findings.0.line', 1)
            ->assertJsonPath('ai_findings.0.explanation', 'This may need attention.')
            ->assertJsonPath('ai_findings.0.suggested_fix', 'Validate and sanitize input.')
            ->assertJsonPath('ai_findings.0.source', 'ai')
            ->assertJsonPath('findings.0.source', 'ai');

        Http::assertSent(function ($request): bool {
            $data = $request->data();
            $prompt = $data['contents'][0]['parts'][0]['text'] ?? '';

            return str_contains((string) $request->url(), 'generativelanguage.googleapis.com')
                && str_contains((string) $request->url(), 'generateContent')
                && ! str_contains((string) $request->url(), 'test-key')
                && $request->hasHeader('x-goog-api-key', 'test-key')
                && str_contains($prompt, 'javascript')
                && str_contains($prompt, 'const value = userInput;')
                && str_contains($data['systemInstruction']['parts'][0]['text'] ?? '', 'never execute')
                && ($data['generationConfig']['responseMimeType'] ?? null) === 'application/json'
                && ($data['generationConfig']['responseSchema']['properties']['findings']['type'] ?? null) === 'ARRAY';
        });
    }

    public function test_malformed_ai_response_is_handled_safely_without_leaking_provider_details(): void
    {
        config()->set('services.gemini.key', 'test-key');

        Http::fake([
            '*' => Http::response([
                'candidates' => [[
                    'content' => ['parts' => [[
                        'text' => 'not valid JSON private-test-key submitted-code',
                    ]]],
                ]],
            ]),
        ]);

        RateLimiter::clear('ai-review:127.0.0.1');

        $response = $this->postJson('/api/analyze', [
            'language' => 'javascript',
            'code' => 'submitted-code',
            'ai_review' => true,
        ])
            ->assertOk()
            ->assertJsonPath('ai_status', 'unavailable')
            ->assertJsonPath('ai_error', 'AI review returned malformed results.');

        $this->assertStringNotContainsString('submitted-code', $response->getContent());
        $this->assertStringNotContainsString('private-test-key', $response->getContent());
    }

    public function test_invalid_ai_findings_are_discarded(): void
    {
        config()->set('services.gemini.key', 'test-key');

        Http::fake([
            '*' => Http::response([
                'candidates' => [[
                    'content' => ['parts' => [[
                        'text' => '{"findings":[{"rule_id":"ai.bad","severity":"urgent","title":"Bad","line":999,"explanation":"No.","suggested_fix":"No."}]}',
                    ]]],
                ]],
            ]),
        ]);

        RateLimiter::clear('ai-review:127.0.0.1');

        $this->postJson('/api/analyze', [
            'language' => 'javascript',
            'code' => 'console.log("debug");',
            'ai_review' => true,
        ])
            ->assertOk()
            ->assertJsonPath('ai_status', 'unavailable')
            ->assertJsonPath('ai_findings', [])
            ->assertJsonPath('ai_error', 'AI review returned malformed results.');
    }

    public function test_malformed_ai_finding_shapes_and_line_numbers_are_rejected(): void
    {
        config()->set('services.gemini.key', 'test-key');

        $invalidFindings = [
            '{"findings":[{"rule_id":"ai.bad","severity":"medium","title":"Bad","line":1.5,"explanation":"No.","suggested_fix":"No."}]}',
            '{"findings":[{"rule_id":"ai.bad","severity":"medium","title":"Bad","line":2,"explanation":"No.","suggested_fix":"No."}]}',
            '{"findings":[{"rule_id":"ai.bad","severity":"medium","title":"Bad","line":1,"explanation":"No."}]}',
        ];

        foreach ($invalidFindings as $invalidFinding) {
            Http::fake([
                '*' => Http::response([
                    'candidates' => [[
                        'content' => ['parts' => [['text' => $invalidFinding]]],
                    ]],
                ]),
            ]);

            RateLimiter::clear('ai-review:127.0.0.1');

            $this->postJson('/api/analyze', [
                'language' => 'javascript',
                'code' => 'const value = userInput;',
                'ai_review' => true,
            ])
                ->assertOk()
                ->assertJsonPath('ai_status', 'unavailable')
                ->assertJsonPath('ai_findings', [])
                ->assertJsonPath('ai_error', 'AI review returned malformed results.');
        }
    }

    public function test_missing_ai_credentials_are_reported_without_leaking_secrets(): void
    {
        config()->set('services.gemini.key', null);
        RateLimiter::clear('ai-review:127.0.0.1');

        $code = 'console.log("submitted-code");';
        $response = $this->postJson('/api/analyze', [
            'language' => 'javascript',
            'code' => $code,
            'ai_review' => true,
        ])
            ->assertOk()
            ->assertJsonPath('ai_status', 'unavailable')
            ->assertJsonPath('ai_error', 'AI review is unavailable because the Gemini API key is not configured.')
            ->assertDontSee($code);

        $this->assertStringNotContainsString($code, $response->getContent());
        Http::assertNothingSent();
    }

    public function test_ai_review_rate_limit_is_enforced(): void
    {
        Http::fake();
        RateLimiter::clear('ai-review:127.0.0.1');

        $key = 'ai-review:127.0.0.1';
        for ($i = 0; $i < 5; $i++) {
            RateLimiter::hit($key, 60);
        }

        $this->postJson('/api/analyze', [
            'language' => 'javascript',
            'code' => 'console.log("debug");',
            'ai_review' => true,
        ])
            ->assertOk()
            ->assertJsonPath('findings.0.rule_id', 'debug.console-log')
            ->assertJsonPath('deterministic_findings.0.source', 'deterministic')
            ->assertJsonPath('ai_status', 'rate_limited')
            ->assertJsonPath('ai_error', 'AI review is temporarily rate-limited. Please try again shortly.')
            ->assertJsonPath('retry_after', fn ($retryAfter) => is_int($retryAfter) && $retryAfter > 0);

        Http::assertNothingSent();
    }

    public function test_provider_error_details_are_not_returned_to_the_client(): void
    {
        $apiKey = 'private-test-gemini-key';
        $code = 'const privateValue = "submitted-code";';
        config()->set('services.gemini.key', $apiKey);
        $handler = new TestHandler;
        Log::swap(new Logger('test', [$handler]));

        Http::fake([
            '*' => Http::response([
                'error' => [
                    'message' => 'Sensitive provider detail '.$apiKey.' '.$code,
                ],
            ], 500),
        ]);

        RateLimiter::clear('ai-review:127.0.0.1');

        try {
            $response = $this->postJson('/api/analyze', [
                'language' => 'javascript',
                'code' => $code,
                'ai_review' => true,
            ])
                ->assertOk()
                ->assertJsonPath('ai_status', 'unavailable')
                ->assertJsonPath('ai_error', 'AI review is temporarily unavailable. Please try again later.');

            $this->assertStringNotContainsString($apiKey, $response->getContent());
            $this->assertStringNotContainsString($code, $response->getContent());
            $this->assertSame([], $handler->getRecords());
        } finally {
            Log::clearResolvedInstance('log');
        }
    }

    public function test_provider_connection_errors_are_reported_safely(): void
    {
        $apiKey = 'private-test-gemini-key';
        $code = 'const privateValue = "submitted-code";';
        config()->set('services.gemini.key', $apiKey);

        Http::fake(function () use ($apiKey, $code) {
            throw new ConnectionException('Timeout with '.$apiKey.' and '.$code);
        });

        RateLimiter::clear('ai-review:127.0.0.1');

        $response = $this->postJson('/api/analyze', [
            'language' => 'javascript',
            'code' => $code,
            'ai_review' => true,
        ])
            ->assertOk()
            ->assertJsonPath('ai_status', 'unavailable')
            ->assertJsonPath('ai_error', 'AI review is temporarily unavailable. Please try again later.');

        $this->assertStringNotContainsString($apiKey, $response->getContent());
        $this->assertStringNotContainsString($code, $response->getContent());
    }

    public function test_gemini_findings_do_not_echo_a_source_secret_in_any_text_field(): void
    {
        $secret = 'MergeGuardSecret-AbC987_xYz654';
        $code = "const apiKey = '{$secret}';";
        $finding = [
            'rule_id' => 'security.input-validation',
            'severity' => 'high',
            'title' => 'Detected value: '.$secret,
            'line' => 1,
            'explanation' => 'Found credential '.$secret,
            'suggested_fix' => 'Replace '.$secret.' with a secure value.',
        ];

        $response = $this->postAiReview($code, [$finding])
            ->assertOk()
            ->assertJsonPath('ai_status', 'completed')
            ->assertJsonCount(1, 'ai_findings');

        $this->assertStringNotContainsString($secret, $response->getContent());
        $this->assertSame('Detected value: [REDACTED]', $response->json('ai_findings.0.title'));
        $this->assertSame('Found credential [REDACTED]', $response->json('ai_findings.0.explanation'));
        $this->assertSame(
            'Replace [REDACTED] with a secure value.',
            $response->json('ai_findings.0.suggested_fix'),
        );
    }

    public function test_gemini_rate_limit_has_a_distinct_provider_status_and_safe_message(): void
    {
        config()->set('services.gemini.key', 'test-key');
        RateLimiter::clear('ai-review:127.0.0.1');

        Http::fake([
            '*' => Http::response([
                'error' => ['message' => 'Sensitive quota details'],
            ], 429),
        ]);

        $response = $this->withServerVariables(['REMOTE_ADDR' => '127.0.0.1'])
            ->postJson('/api/analyze', [
                'language' => 'javascript',
                'code' => 'console.log("deterministic result");',
                'ai_review' => true,
            ])
            ->assertOk()
            ->assertJsonPath('ai_status', 'provider_rate_limited')
            ->assertJsonPath('ai_error', 'AI review is temporarily rate-limited. Please try again in a moment.')
            ->assertJsonPath('ai_findings', [])
            ->assertJsonPath('findings.0.rule_id', 'debug.console-log')
            ->assertJsonPath('findings.0.source', 'deterministic')
            ->assertJsonPath('summary.total', 1);

        $this->assertStringNotContainsString('Sensitive quota details', $response->getContent());
    }

    public function test_equivalent_ai_finding_on_the_same_line_is_removed_and_summary_is_deduplicated(): void
    {
        $response = $this->postAiReview("console.log('debug');", [[
            'rule_id' => 'quality.logging',
            'severity' => 'low',
            'title' => 'Debug logging statement',
            'line' => 1,
            'explanation' => 'console.log writes debug output.',
            'suggested_fix' => 'Remove the debug statement.',
        ]]);

        $response->assertOk()
            ->assertJsonCount(1, 'deterministic_findings')
            ->assertJsonCount(0, 'ai_findings')
            ->assertJsonCount(1, 'findings')
            ->assertJsonPath('findings.0.source', 'deterministic')
            ->assertJsonPath('summary.total', 1)
            ->assertJsonPath('summary.by_severity.low', 1);
    }

    public function test_different_issues_on_the_same_line_are_both_preserved(): void
    {
        $response = $this->postAiReview('console.log(userInput);', [[
            'rule_id' => 'security.input-validation',
            'severity' => 'high',
            'title' => 'Unvalidated user input',
            'line' => 1,
            'explanation' => 'The input is used without validation.',
            'suggested_fix' => 'Validate the input before using it.',
        ]]);

        $response->assertOk()
            ->assertJsonCount(1, 'deterministic_findings')
            ->assertJsonCount(1, 'ai_findings')
            ->assertJsonCount(2, 'findings')
            ->assertJsonPath('summary.total', 2)
            ->assertJsonPath('summary.by_severity.low', 1)
            ->assertJsonPath('summary.by_severity.high', 1);
    }

    public function test_same_issue_on_different_lines_is_preserved(): void
    {
        $deterministicFinding = [
            'rule_id' => 'debug.console-log',
            'severity' => 'low',
            'title' => 'Debug logging statement',
            'line' => 1,
            'explanation' => 'console.log() writes debug output.',
            'suggested_fix' => 'Remove the debug statement.',
            'source' => 'deterministic',
        ];
        $aiFinding = [
            'rule_id' => 'quality.logging',
            'severity' => 'low',
            'title' => 'Debug logging statement',
            'line' => 2,
            'explanation' => 'console.log writes debug output.',
            'suggested_fix' => 'Remove the debug statement.',
            'source' => 'ai',
        ];

        $this->assertSame(
            [$aiFinding],
            (new FindingDeduplicator)->removeDuplicates([$deterministicFinding], [$aiFinding]),
        );
    }

    public function test_python_findings_deduplicate_equivalent_ai_rule_ids(): void
    {
        $rulePairs = [
            ['security.shell-execution', 'security.command-injection'],
            ['security.eval-python', 'security.dynamic-code-execution'],
            ['debug.python-print', 'quality.debug-print'],
        ];
        $deduplicator = new FindingDeduplicator;

        foreach ($rulePairs as [$deterministicRule, $aiRule]) {
            $deterministicFinding = [
                'rule_id' => $deterministicRule,
                'line' => 1,
                'source' => 'deterministic',
            ];
            $aiFinding = [
                'rule_id' => $aiRule,
                'line' => 1,
                'source' => 'ai',
            ];

            $this->assertSame(
                [],
                $deduplicator->removeDuplicates([$deterministicFinding], [$aiFinding]),
            );
        }
    }

    public function test_ai_duplicate_never_removes_the_deterministic_finding(): void
    {
        $response = $this->postAiReview("console.log('debug');", [[
            'rule_id' => 'quality.console-logging',
            'severity' => 'low',
            'title' => 'Console log statement',
            'line' => 1,
            'explanation' => 'console.log leaves debug output in the code.',
            'suggested_fix' => 'Remove the console.log call.',
        ]]);

        $response->assertOk()
            ->assertJsonPath('deterministic_findings.0.rule_id', 'debug.console-log')
            ->assertJsonPath('deterministic_findings.0.source', 'deterministic')
            ->assertJsonPath('findings.0.rule_id', 'debug.console-log')
            ->assertJsonPath('findings.0.source', 'deterministic')
            ->assertJsonCount(0, 'ai_findings');
    }

    public function test_empty_code_is_rejected(): void
    {
        $this->postJson('/api/analyze', [
            'language' => 'php',
            'code' => '',
        ])
            ->assertUnprocessable()
            ->assertJsonValidationErrors('code');
    }

    public function test_whitespace_only_code_is_rejected(): void
    {
        $this->postJson('/api/analyze', [
            'language' => 'php',
            'code' => " \n\t ",
        ])
            ->assertUnprocessable()
            ->assertJsonValidationErrors('code');
    }

    public function test_unsupported_language_is_rejected(): void
    {
        $this->postJson('/api/analyze', [
            'language' => 'ruby',
            'code' => 'puts "hello"',
        ])
            ->assertUnprocessable()
            ->assertJsonValidationErrors('language');
    }

    public function test_code_may_be_exactly_100_kib_but_not_larger(): void
    {
        $exactlyAtLimit = str_repeat('a', AnalyzeCodeRequest::MAX_CODE_BYTES);
        $overLimit = $exactlyAtLimit.'x';

        $this->postJson('/api/analyze', [
            'language' => 'javascript',
            'code' => $exactlyAtLimit,
        ])->assertOk();

        $this->postJson('/api/analyze', [
            'language' => 'javascript',
            'code' => $overLimit,
        ])
            ->assertUnprocessable()
            ->assertJsonValidationErrors('code');

        $this->postJson('/api/analyze', [
            'language' => 'javascript',
            'code' => str_repeat('é', intdiv(AnalyzeCodeRequest::MAX_CODE_BYTES, 2) + 1),
        ])
            ->assertUnprocessable()
            ->assertJsonValidationErrors('code');
    }

    /**
     * @param  array<int, array<string, mixed>>  $findings
     */
    private function postAiReview(string $code, array $findings): TestResponse
    {
        config()->set('services.gemini.key', 'test-key');
        RateLimiter::clear('ai-review:127.0.0.1');

        Http::fake([
            '*' => Http::response([
                'candidates' => [[
                    'content' => [
                        'parts' => [[
                            'text' => json_encode(['findings' => $findings], JSON_THROW_ON_ERROR),
                        ]],
                    ],
                ]],
            ]),
        ]);

        return $this->withServerVariables(['REMOTE_ADDR' => '127.0.0.1'])
            ->postJson('/api/analyze', [
                'language' => 'javascript',
                'code' => $code,
                'ai_review' => true,
            ]);
    }
}
