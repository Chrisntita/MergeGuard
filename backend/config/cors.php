<?php

return [
    'paths' => ['api/*', 'up'],
    'allowed_methods' => ['*'],
    'allowed_origins' => [
        'https://merge-guard-azure.vercel.app',
        env('FRONTEND_URL', 'http://localhost:5173'),
        env('FRONTEND_URL_LOOPBACK', 'http://127.0.0.1:5173'),
    ],
    'allowed_origins_patterns' => [],
    'allowed_headers' => ['*'],
    'exposed_headers' => [],
    'max_age' => 0,
    'supports_credentials' => false,
];
