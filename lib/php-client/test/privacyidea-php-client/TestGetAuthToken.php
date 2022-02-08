<?php

require_once('../../src/Client-Autoloader.php');
require_once('../../vendor/autoload.php');

use PHPUnit\Framework\TestCase;
use InterNations\Component\HttpMock\PHPUnit\HttpMockTrait;

class PrivacyIDEATest extends TestCase
{
    private $pi;

    use HttpMockTrait;

    public static function setUpBeforeClass()
    {
        static::setUpHttpMockBeforeClass('8082', 'localhost');
    }

    public static function tearDownAfterClass()
    {
        static::tearDownHttpMockAfterClass();
    }

    public function setUp()
    {
        $this->setUpHttpMock();
        $this->pi = new PrivacyIDEA('testUserAgent', "http://127.0.0.1:8082");
    }

    public function tearDown()
    {
        $this->tearDownHttpMock();
    }

    public function testGetAuthToken()
    {
        $respAuthToken = '{
         "id": 1,
         "jsonrpc": "2.0",
         "result": {
             "status": true,
             "value": {
                 "token": "eyJhbGciOiJIUz....jdpn9kIjuGRnGejmbFbM"
             }
         },
         "version": "privacyIDEA unknown"
        }';

        $this->http->mock
            ->when()
            ->methodIs('POST')
            ->pathIs('/auth')
            ->then()
            ->body($respAuthToken)
            ->end();
        $this->http->setUp();

        $response = $this->pi->getAuthToken();
        $this->assertFalse($response, "Response is not false.");

        $this->pi->serviceAccountPass = "testPass";
        $this->pi->serviceAccountName = "testAdmin";
        $this->pi->serviceAccountRealm = "testRealm";

        $response = $this->pi->getAuthToken();
        $this->assertEquals('eyJhbGciOiJIUz....jdpn9kIjuGRnGejmbFbM', $response, "Auth token did not match.");

        $this->http->mock
            ->when()
            ->methodIs('POST')
            ->pathIs('/auth')
            ->then()
            ->end();
        $this->http->setUp();

        $response = $this->pi->getAuthToken();
        $this->assertFalse($response);
    }
}
