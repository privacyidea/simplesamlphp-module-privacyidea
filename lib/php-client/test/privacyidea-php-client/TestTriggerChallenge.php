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

    public function testTriggerChallenge()
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

        $respTriggerChallenge = '{
           "detail":{
              "attributes":null,
              "messages":[
                 "Please confirm the authentication on your mobile device!"
              ],
              "multi_challenge":[
                 {
                    "attributes":null,
                    "message":"please enter otp: ",
                    "serial":"OATH00016327",
                    "transaction_id":"08282050332563531714",
                    "type":"hotp"
                 },
                  {
                    "attributes":null,
                    "message":"please verify push",
                    "serial":"PIPU1092340ß1231",
                    "transaction_id":"08282050332563531714",
                    "type":"push"
                 }
              ],
              "serial":"TOTP0002A944",
              "transaction_id":"08282050332563531714",
              "type":"totp"
           },
           "result":{
              "status":true,
              "value":1
           },
           "version":"privacyIDEA 3.5.2",
           "versionnumber":"3.5.2",
           "signature":"rsa_sha256_pss:12345"
        }';

        $this->http->mock
            ->when()
            ->methodIs('POST')
            ->pathIs('/auth')
            ->then()
            ->body($respAuthToken)
            ->end();
        $this->http->setUp();

        $this->http->mock
            ->when()
            ->methodIs('POST')
            ->pathIs('/validate/triggerchallenge')
            ->then()
            ->body(null)
            ->end();
        $this->http->setUp();

        $response = $this->pi->triggerChallenge("testUser");
        $this->assertNull($response, "Response is not NULL.");

        $this->http->mock
            ->when()
            ->methodIs('POST')
            ->pathIs('/validate/triggerchallenge')
            ->then()
            ->body($respTriggerChallenge)
            ->end();
        $this->http->setUp();

        $response = $this->pi->triggerChallenge("");
        $this->assertNull($response, "Response not NULL even if the username not given.");

        $response = $this->pi->triggerChallenge("testUser");
        $this->assertNotNull($response, "Response is NULL.");

        $this->assertEquals("Please confirm the authentication on your mobile device!", $response->messages, "Message did not match.");
        $this->assertEquals("08282050332563531714", $response->transaction_id, "Transaction id did not match.");
        $this->assertEquals($respTriggerChallenge, $response->raw, "Cannot to get the raw response in JSON format!");
        $this->assertTrue($response->status, "Status is not true as expected.");
        $this->assertEquals("1", $response->value, "Value is not false as expected.");
        $this->assertEmpty($response->detailAndAttributes, "detailAndAttributes is not empty as expected.");
        $this->assertNull($response->error, "Error is not null as expected.");

        $this->assertEquals("08282050332563531714", $response->multi_challenge[0]->transaction_id, "Transaction id did not match.");
        $this->assertEquals("please enter otp: ", $response->multi_challenge[0]->message, "Message did not match.");
        $this->assertEquals("OATH00016327", $response->multi_challenge[0]->serial, "Serial did not match.");
        $this->assertEquals("hotp", $response->multi_challenge[0]->type, "Type did not match.");
        $this->assertNull($response->multi_challenge[0]->attributes, "attributes did not match.");

        // Test PIResponse methods: triggeredTokenTypes, pushAvailability, pushMessage, otpMessage
        $this->assertIsArray($response->triggeredTokenTypes());
        $this->assertEquals(["hotp","push"], $response->triggeredTokenTypes());
        $this->assertTrue($response->pushAvailability());
        $this->assertEquals("please verify push", $response->pushMessage());
        $this->assertEquals("please enter otp: ", $response->otpMessage());
    }
}
