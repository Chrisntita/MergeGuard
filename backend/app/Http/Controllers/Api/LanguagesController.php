<?php

namespace App\Http\Controllers\Api;

use App\Services\Analysis\CodeAnalyzer;
use Illuminate\Http\JsonResponse;

class LanguagesController
{
    public function __invoke(): JsonResponse
    {
        $languages = [];

        foreach (CodeAnalyzer::supportedLanguages() as $id => $name) {
            $languages[] = ['id' => $id, 'name' => $name];
        }

        return response()->json(['languages' => $languages]);
    }
}
