<?php

use App\Http\Controllers\Api\AnalysisController;
use App\Http\Controllers\Api\HealthController;
use App\Http\Controllers\Api\LanguagesController;
use Illuminate\Support\Facades\Route;

Route::get('/health', HealthController::class);
Route::get('/languages', LanguagesController::class);
Route::post('/analyze', AnalysisController::class);
