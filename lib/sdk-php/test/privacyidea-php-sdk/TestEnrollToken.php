<?php

require_once('../../src/SDK-Autoloader.php');
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

    public function testEnrollToken()
    {
        // Test case if user already have a token
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

        $respTokenInfo = '{
           "id":1,
           "jsonrpc":"2.0",
           "result":{
              "status":true,
              "value":{
                 "count":3,
                 "current":1,
                 "tokens":[
                    {
                       "active":true,
                       "count":37,
                       "info":{
                          "count_auth":"126",
                          "tokenkind":"software"
                       },
                       "locked":false,
                       "realms":[
                          "testRealm"
                       ],
                       "resolver":"testResolver",
                       "revoked":false
                    }
                 ]
              }
           },
           "version":"privacyIDEA 3.5.2",
           "versionnumber":"3.5.2",
           "signature":"rsa_sha256_pss:12345"
        }';

        $respTokenInit = '{
           "detail":{
              "googleurl":{
                 "description":"URL for google Authenticator",
                 "img":"data:image/png;base64,iVBORw0",
                 "value":"otpauth://totp/TOTP0002A944?secret=Y5D5IM4H274ZI6NRO347QGQ4NPTIOHKL&period=30&digits=6&issuer=privacyIDEA"
              },
              "oathurl":{
                 "description":"URL for OATH token",
                 "img":"data:image/png;base64,iVBORw0",
                 "value":"oathtoken:///addToken?name=TOTP0002A944&lockdown=true&key=c747d43387d7f99479b176f9f81a1c6be6871d4b&timeBased=true"
              },
              "otpkey":{
                 "description":"OTP seed",
                 "img":"data:image/png;base64,iVBORw0",
                 "value":"seed://c747d43387d7f99479b176f9f81a1c6be6871d4b",
                 "value_b32":"Y5D5IM4H274ZI6NRO347QGQ4NPTIOHKL"
              },
              "rollout_state":"",
              "serial":"TOTP0002A944",
              "threadid":140286414018304
           },
           "id":1,
           "jsonrpc":"2.0",
           "result":{
              "status":true,
              "value":true
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
            ->methodIs('GET')
            ->pathIs('/token/')
            ->then()
            ->body($respTokenInfo)
            ->end();
        $this->http->setUp();

        $this->http->mock
            ->when()
            ->methodIs('POST')
            ->pathIs('/token/init')
            ->then()
            ->body($respTokenInit)
            ->end();
        $this->http->setUp();

        $response = $this->pi->enrollToken([
            "user" => "testUser",
            "genkey" => "1",
            "type" => "totp",
            "description" => "Enrolled for Test"]);
        $this->assertNotNull($response, "Response is NULL.");
        $this->assertEmpty($response);

        // Test case if user have no token and we should enroll a new one
        $respTokenInfo = '{
           "id":1,
           "jsonrpc":"2.0",
           "result":{
              "status":true,
              "value":{
                 "count":3,
                 "current":1,
                 "tokens":[]
              }
           },
           "version":"privacyIDEA 3.5.2",
           "versionnumber":"3.5.2",
           "signature":"rsa_sha256_pss:12345"
        }';

        $this->http->mock
            ->when()
            ->methodIs('GET')
            ->pathIs('/token/')
            ->then()
            ->body($respTokenInfo)
            ->end();
        $this->http->setUp();

        $response = $this->pi->enrollToken([
            "user" => "",
            "genkey" => "1",
            "type" => "totp",
            "description" => "Enrolled for Test"]);
        $this->assertEmpty($response, "Without user given enrollToken() should return an empty array.");

        $response = $this->pi->enrollToken([
            "user" => "testUser",
            "genkey" => "",
            "type" => "totp"]);
        $this->assertEmpty($response, "Without genkey given enrollToken() should return an empty array.");

        $response = $this->pi->enrollToken([
            "user" => "testUser",
            "genkey" => "1",
            "type" => ""]);
        $this->assertEmpty($response, "Without type given enrollToken() should return an empty array.");

        $response = $this->pi->enrollToken([
            "user" => "testUser",
            "genkey" => "1",
            "type" => "totp",
            "description" => "Enrolled for Test"]);
        $this->assertNotNull($response, "Response is NULL.");
        $this->assertIsObject($response);
        $this->assertObjectHasAttribute('detail', $response, "Object have no detail attribute.");
        $this->assertEquals("data:image/png;base64,iVBORw0", $response->detail->googleurl->img, "Object have no image data.");
    }
}
