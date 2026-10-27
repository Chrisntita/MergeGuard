<?php

namespace App\Services\Analysis;

class FindingDeduplicator
{
    private const RULE_TYPES = [
        'debug.console-log' => 'debug.logging',
        'debug.python-print' => 'debug.logging',
        'debug.var-dump' => 'debug.dump',
        'security.eval-javascript' => 'code.dynamic-execution',
        'security.eval-php' => 'code.dynamic-execution',
        'security.eval-python' => 'code.dynamic-execution',
        'security.innerhtml-assignment' => 'dom.unsafe-html',
        'security.insecure-http-url' => 'network.insecure-transport',
        'security.hardcoded-secret' => 'security.hardcoded-secret',
        'security.shell-execution' => 'command.shell-execution',
        'security.sql-concatenation' => 'database.sql-injection',
        'security.unserialize-untrusted' => 'serialization.unsafe-unserialize',
    ];

    /**
     * @param  array<int, array<string, mixed>>  $deterministicFindings
     * @param  array<int, array<string, mixed>>  $aiFindings
     * @return array<int, array<string, mixed>>
     */
    public function removeDuplicates(array $deterministicFindings, array $aiFindings): array
    {
        return array_values(array_filter(
            $aiFindings,
            function (array $aiFinding) use ($deterministicFindings): bool {
                foreach ($deterministicFindings as $deterministicFinding) {
                    if (($aiFinding['line'] ?? null) !== ($deterministicFinding['line'] ?? null)) {
                        continue;
                    }

                    $deterministicType = $this->issueType($deterministicFinding);

                    if ($deterministicType !== null && $deterministicType === $this->issueType($aiFinding)) {
                        return false;
                    }
                }

                return true;
            },
        ));
    }

    /**
     * @param  array<string, mixed>  $finding
     */
    private function issueType(array $finding): ?string
    {
        $ruleId = $finding['rule_id'] ?? null;

        if (is_string($ruleId)) {
            if (isset(self::RULE_TYPES[$ruleId])) {
                return self::RULE_TYPES[$ruleId];
            }

            $ruleIdType = $this->issueTypeFromRuleId($ruleId);
            if ($ruleIdType !== null) {
                return $ruleIdType;
            }
        }

        return $this->issueTypeFromText(
            is_string($finding['title'] ?? null) ? $finding['title'] : '',
            is_string($finding['explanation'] ?? null) ? $finding['explanation'] : '',
        );
    }

    private function issueTypeFromRuleId(string $ruleId): ?string
    {
        $aliases = [
            'debug.logging' => '/(?:^|[.-])(?:console-log(?:ging)?|debug-logging|debug-print|python-print|print-statement)(?:$|[.-])/',
            'debug.dump' => '/(?:^|[.-])(?:var-dump|debug-dump)(?:$|[.-])/',
            'code.dynamic-execution' => '/(?:^|[.-])(?:eval|dynamic-code-execution|code-execution)(?:$|[.-])/',
            'command.shell-execution' => '/(?:^|[.-])(?:shell-execution|shell-injection|command-injection|command-execution)(?:$|[.-])/',
            'dom.unsafe-html' => '/(?:^|[.-])(?:innerhtml-assignment|unsafe-innerhtml|dom-xss)(?:$|[.-])/',
            'network.insecure-transport' => '/(?:^|[.-])(?:insecure-http|insecure-http-url|insecure-transport)(?:$|[.-])/',
            'security.hardcoded-secret' => '/(?:^|[.-])(?:hardcoded-secret|hard-coded-secret|exposed-secret)(?:$|[.-])/',
            'database.sql-injection' => '/(?:^|[.-])(?:sql-injection|sql-concatenation)(?:$|[.-])/',
            'serialization.unsafe-unserialize' => '/(?:^|[.-])(?:unserialize-untrusted|unsafe-unserialize|unsafe-deserialization)(?:$|[.-])/',
        ];

        foreach ($aliases as $issueType => $pattern) {
            if (preg_match($pattern, strtolower($ruleId)) === 1) {
                return $issueType;
            }
        }

        return null;
    }

    private function issueTypeFromText(string $title, string $explanation): ?string
    {
        $title = strtolower($title);
        $explanation = strtolower($explanation);

        $matches = [
            'debug.logging' => preg_match('/console\s*\.?\s*log|debug\s+log(?:ging)?/', $title) === 1
                && preg_match('/console\s*\.?\s*log|debug\s+output/', $explanation) === 1,
            'debug.dump' => preg_match('/var_dump|debug dump/', $title) === 1
                && preg_match('/var_dump|debug(?:ging)? output/', $explanation) === 1,
            'code.dynamic-execution' => preg_match('/\beval\s*\(|dynamic(?:ally supplied)? code execution/', $title) === 1
                && preg_match('/\beval\s*\(|dynamic(?:ally supplied)? code/', $explanation) === 1,
            'dom.unsafe-html' => preg_match('/inner\s*html|unsafe html|dom[- ]based xss/', $title) === 1
                && preg_match('/inner\s*html|untrusted.{0,40}html|html injection|cross.site scripting/', $explanation) === 1,
            'network.insecure-transport' => preg_match('/insecure http|insecure transport|unencrypted/', $title) === 1
                && preg_match('/http:\/\/|insecure http|in transit|unencrypted/', $explanation) === 1,
            'security.hardcoded-secret' => preg_match('/hard.?coded secret|exposed secret|possible secret/', $title) === 1
                && preg_match('/hard.?coded secret|secret-like variable|secret.{0,30}(?:literal|source code)/', $explanation) === 1,
            'database.sql-injection' => preg_match('/sql.*(?:injection|concatenation)|(?:injection|concatenation).*sql/', $title) === 1
                && preg_match('/sql query.*concatenat|query.*string concatenat|sql injection/', $explanation) === 1,
            'serialization.unsafe-unserialize' => preg_match('/unserialize|unsafe deserial/', $title) === 1
                && preg_match('/unserialize|deserializ.*(?:untrusted|attacker)/', $explanation) === 1,
        ];

        foreach ($matches as $issueType => $matched) {
            if ($matched) {
                return $issueType;
            }
        }

        return null;
    }
}
