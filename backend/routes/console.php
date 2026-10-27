<?php

use Illuminate\Support\Facades\Artisan;

Artisan::command('about:phase1', function (): void {
    $this->comment('DevPilot Phase 1 API foundation');
})->purpose('Display the DevPilot Phase 1 foundation status');

