<?php

namespace Tests\Feature;

use Tests\TestCase;

class HealthEndpointTest extends TestCase
{
    public function test_api_health_endpoint_returns_ok(): void
    {
        $this->getJson('/api/health')
            ->assertOk()
            ->assertExactJson(['status' => 'ok']);
    }

    public function test_deployed_frontend_origin_is_allowed_for_api_get_requests(): void
    {
        $this->withHeader('Origin', 'https://merge-guard-azure.vercel.app')
            ->getJson('/api/health')
            ->assertOk()
            ->assertHeader('Access-Control-Allow-Origin', 'https://merge-guard-azure.vercel.app');
    }

    public function test_deployed_frontend_origin_is_allowed_for_api_post_preflight(): void
    {
        $response = $this->withHeaders([
            'Origin' => 'https://merge-guard-azure.vercel.app',
            'Access-Control-Request-Method' => 'POST',
            'Access-Control-Request-Headers' => 'content-type',
        ])
            ->options('/api/analyze')
            ->assertNoContent()
            ->assertHeader('Access-Control-Allow-Origin', 'https://merge-guard-azure.vercel.app');

        $this->assertStringContainsString('POST', $response->headers->get('Access-Control-Allow-Methods', ''));
        $this->assertStringContainsString(
            'content-type',
            strtolower($response->headers->get('Access-Control-Allow-Headers', '')),
        );
    }

    public function test_unconfigured_origins_are_not_allowed_by_api_cors(): void
    {
        $this->withHeader('Origin', 'https://unrelated.example')
            ->getJson('/api/health')
            ->assertOk()
            ->assertHeaderMissing('Access-Control-Allow-Origin');
    }
}
