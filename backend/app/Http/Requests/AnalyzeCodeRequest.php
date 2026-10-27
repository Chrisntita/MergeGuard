<?php

namespace App\Http\Requests;

use App\Services\Analysis\CodeAnalyzer;
use Closure;
use Illuminate\Foundation\Http\FormRequest;
use Illuminate\Validation\Rule;

class AnalyzeCodeRequest extends FormRequest
{
    public const MAX_CODE_BYTES = 100 * 1024;

    public function authorize(): bool
    {
        return true;
    }

    public function rules(): array
    {
        return [
            'language' => [
                'required',
                'string',
                Rule::in(array_keys(CodeAnalyzer::supportedLanguages())),
            ],
            'code' => [
                'required',
                'string',
                'max:'.self::MAX_CODE_BYTES,
                function (string $attribute, mixed $value, Closure $fail): void {
                    if (! is_string($value)) {
                        return;
                    }

                    if (trim($value) === '') {
                        $fail('Provide a non-empty code snippet.');

                        return;
                    }

                    if (strlen($value) > self::MAX_CODE_BYTES) {
                        $fail('The code must not exceed 100 KB (102,400 bytes).');
                    }
                },
            ],
            'ai_review' => ['nullable', 'boolean'],
        ];
    }

    public function messages(): array
    {
        return [
            'language.required' => 'Select a programming language.',
            'language.in' => 'The selected programming language is not supported.',
            'code.required' => 'Provide a non-empty code snippet.',
            'code.string' => 'The code must be a source-code string.',
            'code.max' => 'The code must not exceed 100 KB (102,400 bytes).',
        ];
    }
}
