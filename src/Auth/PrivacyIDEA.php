<?php
/*
 * Copyright 2024 NetKnights GmbH - lukas.matusiewicz@netknights.it
 * <p>
 * Licensed under the GNU AFFERO GENERAL PUBLIC LICENSE Version 3;
 * you may not use this file except in compliance with the License.
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

namespace SimpleSAML\Module\privacyidea\Auth;

use RecursiveArrayIterator;
use RecursiveIteratorIterator;

const AUTHENTICATORDATA = "authenticatordata";
const CLIENTDATA = "clientdata";
const SIGNATUREDATA = "signaturedata";
const CREDENTIALID = "credentialid";
const USERHANDLE = "userhandle";
const ASSERTIONCLIENTEXTENSIONS = "assertionclientextensions";

/**
 * PHP client to aid develop plugins for the privacyIDEA authentication server.
 * Include the Client-Autoloader to your PHP file or simply install it using Composer.
 *
 * @author Lukas Matusiewicz <lukas.matusiewicz@netknights.it>
 */
class PrivacyIDEA
{
    /* @var string User agent name which should be forwarded to the privacyIDEA server. */
    private string $userAgent;

    /* @var string URL of the privacyIDEA server. */
    private string $serverURL;

    /* @var string User's realm. */
    private string $realm = "";

    /* @var bool Disable host verification for SSL. */
    private bool $sslVerifyHost = true;

    /* @var bool Disable peer verification for SSL. */
    private bool $sslVerifyPeer = true;

    /* @var string Account name for privacyIDEA service account. Required to use the /validate/triggerchallenge endpoint. */
    private string $serviceAccountName = "";

    /* @var string Password for privacyIDEA service account. Required to use the /validate/triggerchallenge endpoint. */
    private string $serviceAccountPass = "";

    /* @var string Realm for privacyIDEA service account. Optional to use the /validate/triggerchallenge endpoint. */
    private string $serviceAccountRealm = "";

    /* @var bool Send the "client" parameter to allow using the original IP address in the privacyIDEA policies. */
    private bool $forwardClientIP = false;

    /* @var object|null Implementation of the PILog interface. */
    private ?object $logger = null;

    /**
     * PrivacyIDEA constructor.
     * @param $userAgent string User agent.
     * @param $serverURL string privacyIDEA server URL.
     */
    public function __construct(string $userAgent, string $serverURL)
    {
        $this->userAgent = $userAgent;
        $this->serverURL = $serverURL;
    }

    /**
     * Try to authenticate the user by the /validate/check endpoint.
     *
     * @param string $username Username to authenticate.
     * @param string $pass This can be the OTP, but also the PIN to trigger a token or PIN+OTP depending on the configuration of the server.
     * @param string|null $transactionID Optional transaction ID. Used to reference a challenge that was triggered beforehand.
     * @param array|null $headers Optional headers to forward to the server.
     * @return PIResponse|null Returns PIResponse object or null if response was empty or malformed, or some parameter is missing.
     * @throws PIBadRequestException If an error occurs during the request.
     */
    public function validateCheck(string $username, string $pass, string $transactionID = null, array $headers = null): ?PIResponse
    {
        assert('string' === gettype($username));
        assert('string' === gettype($pass));

        if (!empty($username))
        {
            $params["user"] = $username;
            $params["pass"] = $pass;
            if (!empty($transactionID))
            {
                // Add transaction ID in case of challenge response
                $params["transaction_id"] = $transactionID;
            }
            if (empty($headers))
            {
                $headers = array('');
            }
            if ($this->realm)
            {
                $params["realm"] = $this->realm;
            }

            $response = $this->sendRequest($params, $headers, 'POST', '/validate/check');

            $ret = PIResponse::fromJSON($response, $this);
            if ($ret == null)
            {
                $this->debugLog("Server did not respond.");
            }
            return $ret;
        }
        else
        {
            $this->debugLog("Missing username for /validate/check.");
        }
        return null;
    }

    /**
     * Trigger all challenges for the given username.
     * This function requires a service account to be set.
     *
     * @param string $username Username for which the challenges should be triggered.
     * @param array|null $headers Optional headers to forward to the server.
     * @return PIResponse|null Returns PIResponse object or null if response was empty or malformed, or some parameter is missing.
     * @throws PIBadRequestException If an error occurs during the request.
     */
    public function triggerChallenge(string $username, array $headers = null): ?PIResponse
    {
        assert('string' === gettype($username));

        if ($username)
        {
            $authToken = $this->getAuthToken();
            $authTokenHeader = array("authorization:" . $authToken);

            $params = array("user" => $username);

            if ($this->realm)
            {
                $params["realm"] = $this->realm;
            }

            if (!empty($headers))
            {
                $headers = array_merge($headers, $authTokenHeader);
            }
            else
            {
                $headers = $authTokenHeader;
            }

            $response = $this->sendRequest($params, $headers, 'POST', '/validate/triggerchallenge');

            return PIResponse::fromJSON($response, $this);
        }
        else
        {
            $this->debugLog("Username missing!");
        }
        return null;
    }

    /**
     * Poll for the transaction status.
     *
     * @param $transactionID string Transaction ID of the triggered challenge.
     * @param array|null $headers Optional headers to forward to the server.
     * @return bool True if the push request has been accepted, false otherwise.
     * @throws PIBadRequestException If an error occurs during the request.
     */
    public function pollTransaction(string $transactionID, array $headers = null): bool
    {
        assert('string' === gettype($transactionID));

        if (!empty($transactionID))
        {
            $params = array("transaction_id" => $transactionID);
            if (empty($headers))
            {
                $headers = array('');
            }
            $responseJSON = $this->sendRequest($params, $headers, 'GET', '/validate/polltransaction');
            $response = json_decode($responseJSON, true);
            return $response['result']['value'];
        }
        else
        {
            $this->debugLog("TransactionID missing!");
        }
        return false;
    }

    /**
     * Send request to /validate/check endpoint with the data required to authenticate using WebAuthn token.
     *
     * @param string $username Username to authenticate.
     * @param string $transactionID Transaction ID of the triggered challenge.
     * @param string $webAuthnSignResponse WebAuthn sign response.
     * @param string $origin Origin required to authenticate using WebAuthn token.
     * @param array|null $headers Optional headers to forward to the server.
     * @return PIResponse|null Returns PIResponse object or null if response was empty or malformed, or some parameter is missing.
     * @throws PIBadRequestException If an error occurs during the request.
     */
    public function validateCheckWebAuthn(string $username, string $transactionID, string $webAuthnSignResponse, string $origin, array $headers = null): ?PIResponse
    {
        assert('string' === gettype($username));
        assert('string' === gettype($transactionID));
        assert('string' === gettype($webAuthnSignResponse));
        assert('string' === gettype($origin));

        if (!empty($username) && !empty($transactionID) && !empty($webAuthnSignResponse) && !empty($origin))
        {
            // Compose standard validate/check params
            $params["user"] = $username;
            $params["pass"] = "";
            $params["transaction_id"] = $transactionID;

            if ($this->realm)
            {
                $params["realm"] = $this->realm;
            }

            // Additional WebAuthn params
            $tmp = json_decode($webAuthnSignResponse, true);

            $params[CREDENTIALID] = $tmp[CREDENTIALID];
            $params[CLIENTDATA] = $tmp[CLIENTDATA];
            $params[SIGNATUREDATA] = $tmp[SIGNATUREDATA];
            $params[AUTHENTICATORDATA] = $tmp[AUTHENTICATORDATA];

            if (!empty($tmp[USERHANDLE]))
            {
                $params[USERHANDLE] = $tmp[USERHANDLE];
            }
            if (!empty($tmp[ASSERTIONCLIENTEXTENSIONS]))
            {
                $params[ASSERTIONCLIENTEXTENSIONS] = $tmp[ASSERTIONCLIENTEXTENSIONS];
            }

            $originHeader = array("Origin:" . $origin);
            if (!empty($headers))
            {
                $headers = array_merge($headers, $originHeader);
            }
            else
            {
                $headers = $originHeader;
            }

            $response = $this->sendRequest($params, $headers, 'POST', '/validate/check');

            return PIResponse::fromJSON($response, $this);
        }
        else
        {
            // Handle debug message if $username is empty
            $this->debugLog("validateCheckWebAuthn: parameters are incomplete!");
        }
        return null;
    }

    /**
     * Sends request to /validate/check endpoint with the data required to authenticate using U2F token.
     *
     * @param string $username Username to authenticate.
     * @param string $transactionID Transaction ID of the triggered challenge.
     * @param string $u2fSignResponse U2F sign response.
     * @param array|null $headers Optional headers to forward to the server.
     * @return PIResponse|null Returns PIResponse object or null if response was empty or malformed, or some parameter is missing.
     * @throws PIBadRequestException If an error occurs during the request.
     */
    public function validateCheckU2F(string $username, string $transactionID, string $u2fSignResponse, array $headers = null): ?PIResponse
    {
        assert('string' === gettype($username));
        assert('string' === gettype($transactionID));
        assert('string' === gettype($u2fSignResponse));

        // Check if required parameters are set
        if (!empty($username) && !empty($transactionID) && !empty($u2fSignResponse))
        {
            // Compose standard validate/check params
            $params["user"] = $username;
            $params["pass"] = "";
            $params["transaction_id"] = $transactionID;

            if ($this->realm)
            {
                $params["realm"] = $this->realm;
            }

            if (!empty($headers))
            {
                $headers = array('');
            }

            // Additional U2F params from $u2fSignResponse
            $tmp = json_decode($u2fSignResponse, true);
            $params[CLIENTDATA] = $tmp["clientData"];
            $params[SIGNATUREDATA] = $tmp["signatureData"];

            $response = $this->sendRequest($params, $headers, 'POST', '/validate/check');

            return PIResponse::fromJSON($response, $this);
        }
        else
        {
            $this->debugLog("validateCheckU2F parameters are incomplete!");
        }
        return null;
    }

    /**
     * Check if name and pass of service account are set.
     * @return bool
     */
    public function serviceAccountAvailable(): bool
    {
        return (!empty($this->serviceAccountName) && !empty($this->serviceAccountPass));
    }

    /**
     * Retrieves the auth token from the server using the service account. An auth token is required for some requests to the privacyIDEA.
     *
     * @return string Auth token or empty string if the response did not contain a token or no service account is configured.
     * @throws PIBadRequestException If an error occurs during the request.
     */
    public function getAuthToken(): string
    {
        if (!$this->serviceAccountAvailable())
        {
            $this->errorLog("Cannot retrieve auth token without service account!");
            return "";
        }


        $params = array(
            "username" => $this->serviceAccountName,
            "password" => $this->serviceAccountPass
        );

        if ($this->serviceAccountRealm != null && $this->serviceAccountRealm != "")
        {
            $params["realm"] = $this->serviceAccountRealm;
        }

        $response = json_decode($this->sendRequest($params, array(''), 'POST', '/auth'), true);

        if (!empty($response['result']['value']))
        {
            // Ensure an admin account
            if (!empty($response['result']['value']['token']))
            {
                if ($this->findRecursive($response, 'role') != 'admin')
                {
                    $this->debugLog("Auth token was of a user without admin role.");
                    return "";
                }
                return $response['result']['value']['token'];
            }
        }
        $this->debugLog("/auth response did not contain the auth token.");
        return "";
    }

    /**
     * Find key recursively in array.
     *
     * @param array $haystack The array which will be searched.
     * @param string $needle Search string.
     * @return mixed Result of key search.
     */
    public function findRecursive(array $haystack, string $needle): mixed
    {
        assert(is_array($haystack));
        assert(is_string($needle));

        $iterator = new RecursiveArrayIterator($haystack);
        $recursive = new RecursiveIteratorIterator(
            $iterator,
            RecursiveIteratorIterator::SELF_FIRST
        );

        foreach ($recursive as $key => $value)
        {
            if ($key === $needle)
            {
                return $value;
            }
        }
        return false;
    }

    /**
     * Send requests to the endpoint with specified parameters and headers.
     *
     * @param $params array Request parameters.
     * @param $headers array Headers to forward.
     * @param $httpMethod string GET or POST.
     * @param $endpoint string Endpoint of the privacyIDEA API (e.g. /validate/check).
     * @return string Returns a string with the server response.
     * @throws PIBadRequestException If an error occurs.
     */
    public function sendRequest(array $params, array $headers, string $httpMethod, string $endpoint): string
    {
        assert('array' === gettype($params));
        assert('array' === gettype($headers));
        assert('string' === gettype($httpMethod));
        assert('string' === gettype($endpoint));

        // Add the client parameter if wished.
        if ($this->forwardClientIP === true)
        {
            $serverHeaders = $_SERVER;
            foreach (array("X-Forwarded-For", "HTTP_X_FORWARDED_FOR", "REMOTE_ADDR") as $clientKey)
            {
                if (array_key_exists($clientKey, $serverHeaders))
                {
                    $clientIP = $serverHeaders[$clientKey];
                    $this->debugLog("Forwarding Client IP: " . $clientKey . ": " . $clientIP);
                    $params['client'] = $clientIP;
                    break;
                }
            }
        }

        $this->debugLog("Sending " . http_build_query($params, '', ', ') . " to " . $endpoint);

        $completeUrl = $this->serverURL . $endpoint;

        $curlInstance = curl_init();
        curl_setopt($curlInstance, CURLOPT_URL, $completeUrl);
        curl_setopt($curlInstance, CURLOPT_HEADER, true);
        if ($headers)
        {
            curl_setopt($curlInstance, CURLOPT_HTTPHEADER, $headers);
        }
        curl_setopt($curlInstance, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($curlInstance, CURLOPT_USERAGENT, $this->userAgent);
        if ($httpMethod === "POST")
        {
            curl_setopt($curlInstance, CURLOPT_POST, true);
            curl_setopt($curlInstance, CURLOPT_POSTFIELDS, $params);
        }
        elseif ($httpMethod === "PUT")
        {
            curl_setopt($curlInstance, CURLOPT_CUSTOMREQUEST, "PUT");
            curl_setopt($curlInstance, CURLOPT_POSTFIELDS, $params);
        }
        elseif ($httpMethod === "DELETE")
        {
            curl_setopt($curlInstance, CURLOPT_CUSTOMREQUEST, "DELETE");
            curl_setopt($curlInstance, CURLOPT_POSTFIELDS, $params);
        }
        elseif ($httpMethod === "GET")
        {
            $paramsStr = '?';
            if (!empty($params))
            {
                foreach ($params as $key => $value)
                {
                    $paramsStr .= $key . "=" . $value . "&";
                }
            }
            curl_setopt($curlInstance, CURLOPT_URL, $completeUrl . $paramsStr);
        }

        // Disable host and/or peer verification for SSL if configured.
        if ($this->sslVerifyHost === true)
        {
            curl_setopt($curlInstance, CURLOPT_SSL_VERIFYHOST, 2);
        }
        else
        {
            curl_setopt($curlInstance, CURLOPT_SSL_VERIFYHOST, 0);
        }

        if ($this->sslVerifyPeer === true)
        {
            curl_setopt($curlInstance, CURLOPT_SSL_VERIFYPEER, 2);
        }
        else
        {
            curl_setopt($curlInstance, CURLOPT_SSL_VERIFYPEER, 0);
        }

        $response = curl_exec($curlInstance);

        if (!$response)
        {
            // Handle the error
            $curlErrno = curl_errno($curlInstance);
            $this->errorLog("Bad request: " . curl_error($curlInstance) . " errno: " . $curlErrno);
            throw new PIBadRequestException("Unable to reach the authentication server (" . $curlErrno . ")");
        }

        $headerSize = curl_getinfo($curlInstance, CURLINFO_HEADER_SIZE);
        $ret = substr($response, $headerSize);
        curl_close($curlInstance);

        // Log the response
        if ($endpoint != "/auth" && $this->logger != null)
        {
            $retJson = json_decode($ret, true);
            $this->debugLog($endpoint . " returned " . json_encode($retJson, JSON_PRETTY_PRINT));
        }

        // Return decoded response
        return $ret;
    }

    /**
     * This function relays messages to the PILogger implementation.
     * @param string $message Debug message to log.
     */
    function debugLog(string $message): void
    {
        $this->logger?->piDebug("privacyIDEA-PHP-Client: " . $message);
    }

    /**
     * This function relays messages to the PILogger implementation
     * @param string $message Error message to log.
     */
    function errorLog(string $message): void
    {
        $this->logger?->piError("privacyIDEA-PHP-Client: " . $message);
    }

    // Setters

    /**
     * @param string $realm User's realm.
     * @return void
     */
    public function setRealm(string $realm): void
    {
        $this->realm = $realm;
    }

    /**
     * @param bool $sslVerifyHost Disable host verification for SSL.
     * @return void
     */
    public function setSSLVerifyHost(bool $sslVerifyHost): void
    {
        $this->sslVerifyHost = $sslVerifyHost;
    }

    /**
     * @param bool $sslVerifyPeer Disable peer verification for SSL.
     * @return void
     */
    public function setSSLVerifyPeer(bool $sslVerifyPeer): void
    {
        $this->sslVerifyPeer = $sslVerifyPeer;
    }

    /**
     * @param string $serviceAccountName Account name for privacyIDEA service account. Required to use the /validate/triggerchallenge endpoint.
     * @return void
     */
    public function setServiceAccountName(string $serviceAccountName): void
    {
        $this->serviceAccountName = $serviceAccountName;
    }

    /**
     * @param string $serviceAccountPass Password for privacyIDEA service account. Required to use the /validate/triggerchallenge endpoint.
     * @return void
     */
    public function setServiceAccountPass(string $serviceAccountPass): void
    {
        $this->serviceAccountPass = $serviceAccountPass;
    }

    /**
     * @param string $serviceAccountRealm Realm for privacyIDEA service account. Optional to use the /validate/triggerchallenge endpoint.
     * @return void
     */
    public function setServiceAccountRealm(string $serviceAccountRealm): void
    {
        $this->serviceAccountRealm = $serviceAccountRealm;
    }

    /**
     * @param bool $forwardClientIP Send the "client" parameter to allow using the original IP address in the privacyIDEA policies.
     * @return void
     */
    public function setForwardClientIP(bool $forwardClientIP): void
    {
        $this->forwardClientIP = $forwardClientIP;
    }

    /**
     * @param object|null $logger Implementation of the PILog interface.
     * @return void
     */
    public function setLogger(?object $logger): void
    {
        $this->logger = $logger;
    }
}