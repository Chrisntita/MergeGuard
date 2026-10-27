<?php

return [
    'gemini' => [
        'key' => env('GEMINI_API_KEY'),
        'model' => env('GEMINI_MODEL', 'gemini-3.1-flash-lite'),
        'timeout' => (int) env('GEMINI_TIMEOUT', 20),
    ],
];
