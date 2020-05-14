<?php

namespace Xeviant\LaravelPaystack\Test;

use Illuminate\Foundation\Testing\DatabaseMigrations;
use Illuminate\Support\Facades\Event;
use Xeviant\Paystack\Contract\PaystackEventType;

class WebHookTest extends AbstractTestCase
{
    use DatabaseMigrations;

    protected function setUp()
    {
        parent::setUp();

        Event::fake();
    }

    public function testIfWebookRequestIsSuccessfulForALocalEnvironment()
    {
        $event =  PaystackEventType::CHARGE_SUCCESS;
        Event::fake();

        $requestData = [
            'data' => [
                'id' => 1234,
                'amount' => 20000
            ],
            'event' => $event,
        ];

        /**
         * Ensure we are in local environment
         */
        $this->app->detectEnvironment(function () {
            return 'local';
        });

        $hookPath = config('paystack.webhookUrl', '/paystack/hook');

        $response = $this->postJson($hookPath, $requestData);

        $response->assertSuccessful();

        $this->assertDatabaseHas('laravel_paystack_events', [
            'event' => $event,
            'payload' => json_encode($requestData['data']),
        ]);

        Event::assertDispatched($event, 1);
    }

    /**
     * @dataProvider getSupportedPaystackIPs
     * @param $ip
     */
    public function testIfWebookRequestIsSuccessfulForANonLocalEnvironment($ip)
    {
        $event =  PaystackEventType::CHARGE_SUCCESS;
        Event::fake();

        config(['paystack.secretKey' => 'secretKey', 'app.debug' => true]);

        $requestData = [
            'data' => [
                'id' => 1234,
                'amount' => 20000
            ],
            'event' => $event,
        ];

        $signature = hash_hmac('sha512', json_encode($requestData), 'secretKey');

        $this->serverVariables['REMOTE_ADDR'] = $ip;
        $this->serverVariables['HTTP_X_PAYSTACK_SIGNATURE'] = $signature;

        $hookPath = config('paystack.webhookUrl', '/paystack/hook');

        $response = $this->postJson($hookPath, $requestData, [
            'X-Paystack-Signature' => $signature
        ]);

        $response->assertSuccessful();
        $this->assertDatabaseHas('laravel_paystack_events', [
            'event' => $event,
            'payload' => json_encode($requestData['data']),
        ]);

        Event::assertDispatched($event, 1);
    }

    /**
     * @dataProvider getSupportedPaystackIPs
     * @param $ip
     */
    public function testIfWebookRequestIsDeniedForANonLocalEnvironmentWhenSignatureIsInvalid($ip)
    {
        $event =  PaystackEventType::CHARGE_SUCCESS;
        Event::fake();

        config(['paystack.secretKey' => 'secretKey']);

        $requestData = [
            'data' => [
                'id' => 1234,
                'amount' => 20000
            ],
            'event' => $event,
        ];

        $signature = hash_hmac('sha512', json_encode([]), 'secretKey');

        $this->serverVariables['REMOTE_ADDR'] = $ip;
        $this->serverVariables['HTTP_X_PAYSTACK_SIGNATURE'] = $signature;

        $hookPath = config('paystack.webhookUrl', '/paystack/hook');

        $response = $this->postJson($hookPath, $requestData, [
            'X-Paystack-Signature' => $signature
        ]);

        $response->assertForbidden();
    }

    /**
     * @dataProvider getUnsupportedPaystackIPs
     * @param $ip
     */
    public function testIfWebookRequestIsDeniedAcessForANonLocalEnvironmentWhenIpIsUnsupported($ip)
    {
        $this->serverVariables['REMOTE_ADDR'] = $ip;

        $requestData = [
            'data' => [
                'id' => 1234,
                'amount' => 20000
            ],
            'event' => 'event',
        ];

        $hookPath = config('paystack.webhookUrl', '/paystack/hook');

        $response = $this->postJson($hookPath, $requestData);

        $response->assertForbidden();
    }

    /**
     * These are the official paystack IPs that are supported
     *
     * @see https://developers.paystack.co/v2.0/docs/events
     *
     * @return \string[][]
     */
    public function getSupportedPaystackIPs()
    {
        return [
            ['52.31.139.75'],
            ['52.49.173.169'],
            ['52.214.14.220'],
        ];
    }

    public function getUnsupportedPaystackIPs()
    {
        return [
            ['52.31.139.751'],
            ['52.49.173.168'],
            ['52.214.14.221'],
        ];
    }
}