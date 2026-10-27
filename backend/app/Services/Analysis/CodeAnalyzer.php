<?php

namespace App\Services\Analysis;

class CodeAnalyzer
{
    /**
     * @var array<string, string>
     */
    private const LANGUAGES = [
        'php' => 'PHP',
        'javascript' => 'JavaScript',
        'typescript' => 'TypeScript',
        'python' => 'Python',
    ];

    /**
     * @return array<string, string>
     */
    public static function supportedLanguages(): array
    {
        return self::LANGUAGES;
    }

    /**
     * @return array<int, array{
     *     rule_id: string,
     *     severity: string,
     *     title: string,
     *     line: int,
     *     explanation: string,
     *     suggested_fix: string
     * }>
     */
    public function analyze(string $language, string $code): array
    {
        $findings = [];
        $seen = [];
        $lines = preg_split('/\R/', $code) ?: [];
        $inBlockComment = false;
        $inPythonTripleQuotedString = null;

        foreach ($lines as $index => $line) {
            $lineNumber = $index + 1;
            $javascriptCode = $line;
            $javascriptStringLiterals = [];
            $pythonCode = $line;
            $pythonSourceWithoutComments = $line;

            if (in_array($language, ['javascript', 'typescript'], true)) {
                [$javascriptCode, $javascriptStringLiterals] = $this->maskJavaScriptStringsAndComments(
                    $line,
                    $inBlockComment,
                );
            }

            if ($language === 'python') {
                [$pythonCode, $pythonSourceWithoutComments] = $this->maskPythonStringsAndComments(
                    $line,
                    $inPythonTripleQuotedString,
                );
            }

            if (in_array($language, ['javascript', 'typescript'], true)) {
                $this->addFindingIf(
                    $findings,
                    $seen,
                    $this->matchesJavaScriptConsoleLog($line),
                    'debug.console-log',
                    'low',
                    'Debug logging statement',
                    $lineNumber,
                    'console.log() writes debug output that may not belong in production code.',
                    'Remove the debug statement or replace it with the application logger.',
                );

                $this->addFindingIf(
                    $findings,
                    $seen,
                    $this->matchesJavaScriptEval($line),
                    'security.eval-javascript',
                    'high',
                    'Use of eval() in client-side code',
                    $lineNumber,
                    'eval() executes dynamically supplied code and can be abused to run attacker-controlled logic.',
                    'Avoid eval() entirely; use explicit parsing or safe structured APIs instead.',
                );

                $this->addFindingIf(
                    $findings,
                    $seen,
                    $this->matchesInnerHtmlAssignment($javascriptCode),
                    'security.innerhtml-assignment',
                    'high',
                    'Untrusted content written to innerHTML',
                    $lineNumber,
                    'Writing untrusted input into innerHTML can permit script injection or unsafe HTML injection.',
                    'Prefer textContent or a sanitizer before inserting user-controlled markup into the DOM.',
                );

                $this->addFindingIf(
                    $findings,
                    $seen,
                    $this->matchesInsecureHttpUrl($javascriptCode, $javascriptStringLiterals),
                    'security.insecure-http-url',
                    'medium',
                    'Insecure HTTP URL in network request',
                    $lineNumber,
                    'An HTTP URL can expose credentials, tokens, and sensitive data in transit.',
                    'Use HTTPS for production endpoints and prefer authenticated, encrypted APIs.',
                );
            }

            if ($language === 'php') {
                $this->addFindingIf(
                    $findings,
                    $seen,
                    $this->matchesPhpVarDump($line),
                    'debug.var-dump',
                    'low',
                    'Debug dump statement',
                    $lineNumber,
                    'var_dump() emits debugging output that may expose sensitive values or corrupt a response.',
                    'Remove the dump or guard it behind a development-only environment check.',
                );

                $this->addFindingIf(
                    $findings,
                    $seen,
                    $this->matchesPhpEval($line),
                    'security.eval-php',
                    'high',
                    'Use of eval() in PHP',
                    $lineNumber,
                    'eval() executes code supplied as a string and is a common injection vector.',
                    'Do not evaluate dynamic strings; parse them explicitly or replace the pattern with safer logic.',
                );

                $this->addFindingIf(
                    $findings,
                    $seen,
                    $this->matchesPhpSqlConcatenation($line),
                    'security.sql-concatenation',
                    'high',
                    'SQL built from untrusted string concatenation',
                    $lineNumber,
                    'A SQL query assembled by concatenating variables can allow injection if the value is not safely bound.',
                    'Use prepared statements and parameterized queries instead of string concatenation.',
                );

                $this->addFindingIf(
                    $findings,
                    $seen,
                    $this->matchesUnserializeOfUntrustedData($line),
                    'security.unserialize-untrusted',
                    'high',
                    'Unsafe unserialize() of untrusted input',
                    $lineNumber,
                    'unserialize() can instantiate code paths from attacker-controlled payloads if the input is not trusted.',
                    'Avoid unserialize() on user-controlled data; prefer JSON or a trusted serialization format with validation.',
                );
            }

            if ($language === 'python') {
                $this->addFindingIf(
                    $findings,
                    $seen,
                    $this->matchesPythonShellExecution($pythonCode),
                    'security.shell-execution',
                    'high',
                    'Shell execution uses potentially untrusted input',
                    $lineNumber,
                    'A subprocess call enables shell interpretation while using a value that may be influenced by external input.',
                    'Avoid shell=True and pass a fixed executable with an argument list; validate and constrain each argument.',
                );

                $this->addFindingIf(
                    $findings,
                    $seen,
                    $this->matchesPythonDynamicExecution($pythonCode),
                    'security.eval-python',
                    'high',
                    'Dynamic code execution in Python',
                    $lineNumber,
                    'eval() and exec() interpret a string as Python code and can execute attacker-controlled logic.',
                    'Avoid eval() and exec(); use explicit parsing or structured data instead.',
                );

                $this->addFindingIf(
                    $findings,
                    $seen,
                    $this->containsPythonHardCodedSecret($line, $pythonCode),
                    'security.hardcoded-secret',
                    'high',
                    'Possible hard-coded secret',
                    $lineNumber,
                    'A secret-like variable is assigned a long, high-variation string literal.',
                    'Load the value from a server-side environment variable or secret manager and rotate it if it was exposed.',
                );

                $this->addFindingIf(
                    $findings,
                    $seen,
                    $this->matchesPythonPrint($pythonCode),
                    'debug.python-print',
                    'low',
                    'Python print statement',
                    $lineNumber,
                    'print() writes directly to standard output and is often left behind as debug output.',
                    'Remove temporary print() calls or use the application logger where output is required.',
                );

                $this->addFindingIf(
                    $findings,
                    $seen,
                    $this->matchesPythonSqlConstruction($pythonCode, $pythonSourceWithoutComments),
                    'security.sql-concatenation',
                    'high',
                    'SQL built from potentially untrusted input',
                    $lineNumber,
                    'SQL text appears to be combined or interpolated with a value that may be externally controlled.',
                    'Use parameterized queries and pass values separately to the database driver.',
                );
            }

            if ($language !== 'python') {
                $this->addFindingIf(
                    $findings,
                    $seen,
                    $this->containsHardCodedSecret($line),
                    'security.hardcoded-secret',
                    'high',
                    'Possible hard-coded secret',
                    $lineNumber,
                    'A secret-like variable is assigned a long, high-variation string literal.',
                    'Load the value from a server-side environment variable or secret manager and rotate it if it was exposed.',
                );
            }
        }

        usort(
            $findings,
            static fn (array $left, array $right): int => [$left['line'], $left['rule_id']]
                <=> [$right['line'], $right['rule_id']],
        );

        return $findings;
    }

    private function addFindingIf(
        array &$findings,
        array &$seen,
        bool $shouldAdd,
        string $ruleId,
        string $severity,
        string $title,
        int $line,
        string $explanation,
        string $suggestedFix,
    ): void {
        if (! $shouldAdd) {
            return;
        }

        $key = $line.':'.$ruleId;

        if (isset($seen[$key])) {
            return;
        }

        $seen[$key] = true;
        $findings[] = $this->finding(
            $ruleId,
            $severity,
            $title,
            $line,
            $explanation,
            $suggestedFix,
        );
    }

    private function matchesJavaScriptConsoleLog(string $line): bool
    {
        if ($this->isCommentLine($line)) {
            return false;
        }

        $sanitized = $this->stripQuotedStrings($line);

        return preg_match('/(?<![A-Za-z0-9_$])console\s*\.\s*log\s*\(/', $sanitized) === 1;
    }

    private function matchesJavaScriptEval(string $line): bool
    {
        if ($this->isCommentLine($line)) {
            return false;
        }

        $sanitized = $this->stripQuotedStrings($line);

        return preg_match('/(?<![A-Za-z0-9_$])eval\s*\(/', $sanitized) === 1;
    }

    private function matchesInnerHtmlAssignment(string $line): bool
    {
        if (preg_match('/\binnerHTML\s*=\s*/i', $line) !== 1) {
            return false;
        }

        return preg_match('/\b(?:user|input|data|payload|response|result|text|html|content|value|message|query)\w*\b/i', $line) === 1;
    }

    private function matchesInsecureHttpUrl(string $line, array $stringLiterals): bool
    {
        $patterns = [
            '/(?:fetch|axios\.\w+)\s*\(\s*__MG_STRING_(\d+)__/i',
            '/(?:new\s+XMLHttpRequest|http\.request)[^\n]*?__MG_STRING_(\d+)__/i',
        ];

        foreach ($patterns as $pattern) {
            if (preg_match($pattern, $line, $matches) === 1
                && isset($stringLiterals[(int) $matches[1]])
                && str_starts_with(strtolower($stringLiterals[(int) $matches[1]]), 'http://')) {
                return true;
            }
        }

        return false;
    }

    /**
     * Replace strings and comments with markers so code-like text within them is
     * not interpreted as executable syntax by the line-oriented rules.
     *
     * @return array{string, array<int, string>}
     */
    private function maskJavaScriptStringsAndComments(
        string $line,
        bool &$inBlockComment,
    ): array {
        $masked = '';
        $literals = [];
        $length = strlen($line);
        $index = 0;

        while ($index < $length) {
            if ($inBlockComment) {
                $end = strpos($line, '*/', $index);
                if ($end === false) {
                    $masked .= str_repeat(' ', $length - $index);
                    break;
                }

                $masked .= str_repeat(' ', $end + 2 - $index);
                $index = $end + 2;
                $inBlockComment = false;

                continue;
            }

            if ($line[$index] === '/' && ($line[$index + 1] ?? '') === '/') {
                $masked .= str_repeat(' ', $length - $index);
                break;
            }

            if ($line[$index] === '/' && ($line[$index + 1] ?? '') === '*') {
                $masked .= '  ';
                $index += 2;
                $inBlockComment = true;

                continue;
            }

            $delimiter = $line[$index];
            if ($delimiter === '`') {
                $end = $this->findUnescapedDelimiter($line, '`', $index + 1);
                if ($end === null) {
                    $masked .= substr($line, $index);
                    break;
                }

                $literal = substr($line, $index + 1, $end - $index - 1);
                if (str_contains($literal, '${')) {
                    $masked .= substr($line, $index, $end - $index + 1);
                } else {
                    $literalIndex = count($literals);
                    $literals[$literalIndex] = $literal;
                    $masked .= '__MG_STRING_'.$literalIndex.'__';
                }
                $index = $end + 1;

                continue;
            }

            if ($delimiter === "'" || $delimiter === '"') {
                $end = $this->findUnescapedDelimiter($line, $delimiter, $index + 1);
                if ($end === null) {
                    $masked .= str_repeat(' ', $length - $index);
                    break;
                }

                $literalIndex = count($literals);
                $literals[$literalIndex] = substr($line, $index + 1, $end - $index - 1);
                $masked .= '__MG_STRING_'.$literalIndex.'__';
                $index = $end + 1;

                continue;
            }

            $masked .= $line[$index];
            $index++;
        }

        return [$masked, $literals];
    }

    private function findUnescapedDelimiter(string $line, string $delimiter, int $start): ?int
    {
        $escaped = false;

        for ($index = $start, $length = strlen($line); $index < $length; $index++) {
            if ($escaped) {
                $escaped = false;

                continue;
            }

            if ($line[$index] === '\\') {
                $escaped = true;

                continue;
            }

            if ($line[$index] === $delimiter) {
                return $index;
            }
        }

        return null;
    }

    private function matchesPhpVarDump(string $line): bool
    {
        if ($this->isCommentLine($line)) {
            return false;
        }

        $sanitized = $this->stripQuotedStrings($line);

        return preg_match('/(?<![A-Za-z0-9_])var_dump\s*\(/i', $sanitized) === 1;
    }

    private function matchesPhpEval(string $line): bool
    {
        if ($this->isCommentLine($line)) {
            return false;
        }

        $sanitized = $this->stripQuotedStrings($line);

        return preg_match('/(?<![A-Za-z0-9_])eval\s*\(/i', $sanitized) === 1;
    }

    private function matchesPhpSqlConcatenation(string $line): bool
    {
        if ($this->isCommentLine($line)) {
            return false;
        }

        if (preg_match('/\b(?:SELECT|INSERT|UPDATE|DELETE|CREATE|ALTER|DROP)\b/i', $line) !== 1) {
            return false;
        }

        return preg_match('/\.\s*(?:\$[A-Za-z_][A-Za-z0-9_]*|[\'\"])/i', $line) === 1
            || preg_match('/(?:\$[A-Za-z_][A-Za-z0-9_]*)\s*\.\s*(?:[\'\"]|\$[A-Za-z_][A-Za-z0-9_]*)/i', $line) === 1;
    }

    private function matchesUnserializeOfUntrustedData(string $line): bool
    {
        if ($this->isCommentLine($line)) {
            return false;
        }

        return preg_match(
            '/\bunserialize\s*\(\s*(?:\$_(?:GET|POST|REQUEST|COOKIE|SERVER)|\$[A-Za-z_][A-Za-z0-9_]*(?:input|data|payload|request|user|raw|content|json)[A-Za-z0-9_]*)/i',
            $line,
        ) === 1;
    }

    /**
     * Mask Python strings and comments for syntax checks while retaining string
     * literals separately for the narrowly scoped SQL-construction check.
     *
     * @return array{string, string}
     */
    private function maskPythonStringsAndComments(
        string $line,
        ?string &$inTripleQuotedString,
    ): array {
        $masked = '';
        $sourceWithoutComments = '';
        $length = strlen($line);
        $index = 0;

        while ($index < $length) {
            if ($inTripleQuotedString !== null) {
                $end = strpos($line, $inTripleQuotedString, $index);
                if ($end === false) {
                    $remaining = substr($line, $index);
                    $masked .= str_repeat(' ', strlen($remaining));
                    $sourceWithoutComments .= $remaining;

                    break;
                }

                $literal = substr($line, $index, $end + 3 - $index);
                $masked .= str_repeat(' ', strlen($literal));
                $sourceWithoutComments .= $literal;
                $index = $end + 3;
                $inTripleQuotedString = null;

                continue;
            }

            if ($line[$index] === '#') {
                $masked .= str_repeat(' ', $length - $index);
                $sourceWithoutComments .= str_repeat(' ', $length - $index);

                break;
            }

            $literalStart = $index;
            $prefix = '';
            if (preg_match('/\A(?:(?i:f[r]?|r[f]?|[rub]))?(?=[\'"])/', substr($line, $index), $prefixMatch) === 1) {
                $prefix = $prefixMatch[0];
                $quoteIndex = $index + strlen($prefix);
            } elseif ($line[$index] === "'" || $line[$index] === '"') {
                $quoteIndex = $index;
            } else {
                $masked .= $line[$index];
                $sourceWithoutComments .= $line[$index];
                $index++;

                continue;
            }

            $quote = $line[$quoteIndex];
            $triple = substr($line, $quoteIndex, 3) === str_repeat($quote, 3);
            $delimiter = $triple ? str_repeat($quote, 3) : $quote;
            $contentStart = $quoteIndex + strlen($delimiter);
            $end = $this->findPythonStringEnd($line, $delimiter, $contentStart);

            if ($end === null && $triple) {
                $literal = substr($line, $literalStart);
                $masked .= str_repeat(' ', strlen($literal));
                $sourceWithoutComments .= $literal;
                $inTripleQuotedString = $delimiter;

                break;
            }

            if ($end === null) {
                $literal = substr($line, $literalStart);
                $masked .= str_repeat(' ', strlen($literal));
                $sourceWithoutComments .= $literal;

                break;
            }

            $literalEnd = $end + strlen($delimiter);
            $literal = substr($line, $literalStart, $literalEnd - $literalStart);
            $maskedLiteral = str_repeat(' ', strlen($literal));
            $isFString = str_contains(strtolower($prefix), 'f');

            if ($isFString && ! $triple) {
                $content = substr($line, $contentStart, $end - $contentStart);
                $maskedLiteral = $this->maskPythonFStringContent(
                    $literal,
                    $content,
                    strlen($prefix) + strlen($delimiter),
                );
            }

            $masked .= $maskedLiteral;
            $sourceWithoutComments .= $literal;
            $index = $literalEnd;
        }

        return [$masked, $sourceWithoutComments];
    }

    private function findPythonStringEnd(string $line, string $delimiter, int $start): ?int
    {
        $escaped = false;

        for ($index = $start, $length = strlen($line); $index < $length; $index++) {
            if ($escaped) {
                $escaped = false;

                continue;
            }

            if ($line[$index] === '\\') {
                $escaped = true;

                continue;
            }

            if (substr($line, $index, strlen($delimiter)) === $delimiter) {
                return $index;
            }
        }

        return null;
    }

    private function maskPythonFStringContent(
        string $literal,
        string $content,
        int $contentOffset,
    ): string {
        $masked = str_repeat(' ', strlen($literal));
        $length = strlen($content);

        for ($index = 0; $index < $length; $index++) {
            if ($content[$index] !== '{') {
                continue;
            }

            if (($content[$index + 1] ?? '') === '{') {
                $index++;

                continue;
            }

            $end = strpos($content, '}', $index + 1);
            if ($end === false) {
                break;
            }

            $expression = substr($content, $index + 1, $end - $index - 1);
            $offset = $contentOffset + $index + 1;
            for ($expressionIndex = 0, $expressionLength = strlen($expression); $expressionIndex < $expressionLength; $expressionIndex++) {
                $masked[$offset + $expressionIndex] = $expression[$expressionIndex];
            }
            $index = $end;
        }

        return $masked;
    }

    private function matchesPythonShellExecution(string $line): bool
    {
        $hasShellEnabledSubprocess = preg_match(
            '/\bsubprocess\s*\.\s*(?:run|Popen|call|check_call|check_output)\s*\(/i',
            $line,
        ) === 1
            && preg_match('/\bshell\s*=\s*True\b/', $line) === 1;
        $usesShellCommand = preg_match('/\bos\s*\.\s*(?:system|popen)\s*\(/i', $line) === 1;

        return ($hasShellEnabledSubprocess || $usesShellCommand)
            && $this->containsPythonUserControlledValue($line);
    }

    private function matchesPythonDynamicExecution(string $line): bool
    {
        return preg_match('/(?<![A-Za-z0-9_.])(?:eval|exec)\s*\(/', $line) === 1;
    }

    private function containsPythonHardCodedSecret(string $line, string $code): bool
    {
        if (preg_match(
            '/^\s*(?:(?:self|cls)\s*\.\s*)?([A-Za-z_]\w*)\s*(?::\s*[^=]+)?\s*=/',
            $code,
            $assignment,
        ) !== 1
            || preg_match(
                '/^\s*(?:(?:self|cls)\s*\.\s*)?[A-Za-z_]\w*\s*(?::\s*[^=]+)?\s*=\s*(?:[rubf]{0,2})?[\'"]([^\'"]*)[\'"]/',
                $line,
                $value,
            ) !== 1) {
            return false;
        }

        if (preg_match('/(?:api[_-]?key|secret|token|password|credential|private[_-]?key)/i', $assignment[1]) !== 1) {
            return false;
        }

        return $this->isLikelySecretValue($value[1]);
    }

    private function matchesPythonPrint(string $line): bool
    {
        return preg_match('/(?<![A-Za-z0-9_.])print\s*\(/', $line) === 1;
    }

    private function matchesPythonSqlConstruction(string $code, string $sourceWithoutComments): bool
    {
        if ($this->containsPythonUserControlledValue($code) !== true) {
            return false;
        }

        $sqlKeywords = '(?:SELECT|INSERT|UPDATE|DELETE|REPLACE)';
        $sqlLiteral = '/[\'"][^\'"]*\b'.$sqlKeywords.'\b[^\'"]*[\'"]/i';
        $quotedSqlConcat = '/[\'"][^\'"]*\b'.$sqlKeywords.'\b[^\'"]*[\'"]\s*\+\s*[A-Za-z_]\w*|\b[A-Za-z_]\w*\s*\+\s*[\'"][^\'"]*\b'.$sqlKeywords.'\b[^\'"]*[\'"]/i';
        $quotedSqlFormat = '/[\'"][^\'"]*\b'.$sqlKeywords.'\b[^\'"]*[\'"]\s*\.\s*format\s*\(/i';
        $quotedSqlPercent = '/[\'"][^\'"]*\b'.$sqlKeywords.'\b[^\'"]*[\'"]\s*%\s*(?:\(|[A-Za-z_])/i';
        $fStringSqlInterpolation = '/\bf[\'"][^\'"]*\b'.$sqlKeywords.'\b[^\'"]*\{[^}]+\}[^\'"]*[\'"]/i';

        if (preg_match($sqlLiteral, $sourceWithoutComments) !== 1) {
            return false;
        }

        return preg_match($quotedSqlConcat, $sourceWithoutComments) === 1
            || preg_match($quotedSqlFormat, $sourceWithoutComments) === 1
            || preg_match($quotedSqlPercent, $sourceWithoutComments) === 1
            || preg_match($fStringSqlInterpolation, $sourceWithoutComments) === 1;
    }

    private function containsPythonUserControlledValue(string $line): bool
    {
        return preg_match(
            '/\b(?:user|input|request|args|argv|payload|form|query|data|param|raw|body)[A-Za-z0-9_]*\b/i',
            $line,
        ) === 1;
    }

    private function containsHardCodedSecret(string $line): bool
    {
        if ($this->isCommentLine($line)) {
            return false;
        }

        $pattern = '/(?:api[_-]?key|secret|token|password|credential|private[_-]?key)[A-Za-z0-9_]*\s*(?:=|:)\s*([\'\"])([^\'\"]{24,})\1/i';

        if (preg_match_all($pattern, $line, $matches, PREG_SET_ORDER) === false) {
            return false;
        }

        foreach ($matches as $match) {
            $value = $match[2];

            if ($this->isLikelySecretValue($value)) {
                return true;
            }
        }

        return false;
    }

    private function isLikelySecretValue(string $value): bool
    {
        if ($this->isLikelyPlaceholder($value)) {
            return false;
        }

        $characterClasses = [
            preg_match('/[a-z]/', $value) === 1,
            preg_match('/[A-Z]/', $value) === 1,
            preg_match('/[0-9]/', $value) === 1,
            preg_match('/[^A-Za-z0-9]/', $value) === 1,
        ];

        return strlen($value) >= 24 && count(array_filter($characterClasses)) >= 3;
    }

    private function isLikelyPlaceholder(string $value): bool
    {
        $normalized = strtolower(trim($value));

        return preg_match('/(?:^|[_-])(example|sample|placeholder|demo|dummy|test|local|development|replace[_-]?with|your_.*_here)(?:$|[_-])/i', $normalized) === 1
            || preg_match('/\b(?:example|sample|placeholder|demo|dummy|test|local|development)\b/i', $normalized) === 1;
    }

    private function stripQuotedStrings(string $line): string
    {
        return preg_replace('/([\'\"])(?:\\.|(?!\1).)*\1/', ' ', $line) ?? $line;
    }

    private function isCommentLine(string $line): bool
    {
        return preg_match('/^\s*(?:\/\/|#|\/\*|\*)/', $line) === 1;
    }

    /**
     * @return array{
     *     rule_id: string,
     *     severity: string,
     *     title: string,
     *     line: int,
     *     explanation: string,
     *     suggested_fix: string
     * }
     */
    private function finding(
        string $ruleId,
        string $severity,
        string $title,
        int $line,
        string $explanation,
        string $suggestedFix,
    ): array {
        return [
            'rule_id' => $ruleId,
            'severity' => $severity,
            'title' => $title,
            'line' => $line,
            'explanation' => $explanation,
            'suggested_fix' => $suggestedFix,
        ];
    }
}
