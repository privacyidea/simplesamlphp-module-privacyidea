<?php
const AUTHENTICATORDATA = "authenticatordata";
const CLIENTDATA = "clientdata";
const SIGNATUREDATA = "signaturedata";
const CREDENTIALID = "credentialid";
const USERHANDLE = "userhandle";
const ASSERTIONCLIENTEXTENSIONS = "assertionclientextensions";

/**
 * All the API requests which you need are already done and set to methods in this class.
 * All you have to do is include the SDK-Autoloader to your PHP file
 * and call the methods adding the needed parameters.
 *
 * @author Lukas Matusiewicz <lukas.matusiewicz@netknights.it>
 */
class PrivacyIDEA
{
    /* @var string Plugins name which must to be verified in privacyIDEA. */
    public $userAgent = "";
    /* @var string This is the URL to your privacyIDEA server. */
    public $serverURL = "";
    /* @var string Here is realm of users account. */
    public $realm = "";
    /* @var bool You can decide if you want to verify your ssl certificate. */
    public $sslVerifyHost = true;
    /* @var bool You can decide if you want to verify your ssl certificate. */
    public $sslVerifyPeer = true;
    /* @var string Username to your service account. You need it to get auth token which is needed by some PI API requests. */
    public $serviceAccountName = "";
    /* @var string Password to your service account. You need it to get auth token which is needed by some PI API requests. */
    public $serviceAccountPass = "";
    /* @var string If needed you can add it too. */
    public $serviceAccountRealm = "";
    /* @var object This object will deliver PI debug and error messages to your plugin so you can log it wherever you want. */
    public $logger = null;

    /**
     * PrivacyIDEA constructor.
     * @param $userAgent string the user agent that should set in the http header
     * @param $serverURL string the url of the privacyIDEA server
     */
    public function __construct($userAgent, $serverURL)
    {
        $this->userAgent = $userAgent;
        $this->serverURL = $serverURL;
    }

    /**
     * This function collect the debug messages and send it to PILog.php
     * @param $message
     */
    function debugLog($message)
    {
        if ($this->logger != null)
        {
            $this->logger->piDebug($message);
        }
    }

    /**
     * This function collect the error messages and send it to PILog.php
     * @param $message
     */
    function errorLog($message)
    {
        if ($this->logger != null)
        {
            $this->logger->piError($message);
        }
    }

    /**
     * Handle validateCheck using user's username, password and if challenge response - transaction_id.
     *
     * @param $username string Must be set
     * @param $pass string Must be set
     * @param null $transactionID Optional transaction ID. Used to reference a challenge that was triggered beforehand.
     * @return PIResponse|null This method returns an PIResponse object which contains all the useful information from the PI server. In case of error returns null.
     * @throws PIBadRequestException
     */
    public function validateCheck($username, $pass, $transactionID = null)
    {
        assert('string' === gettype($username));
        assert('string' === gettype($pass));

        // Log entry of the validateCheck()
        $this->debugLog("validateCheck() with user=" . $username . ", pass=" . $pass . " and if is set transactionID " . $transactionID);

        //Check if parameters are set
        if (!empty($username) || !empty($pass))
        {
            $params["user"] = $username;
            $params["pass"] = $pass;
            if (!empty($transactionID))
            {
                //Add transaction ID in case of challenge response
                $params["transaction_id"] = $transactionID;
            }
            if ($this->realm)
            {
                $params["realm"] = $this->realm;
            }

            //Call send_request function to handle an API Request using $parameters and return it.
            $response = $this->sendRequest($params, array(''), 'POST', '/validate/check');

            //Return the response from /validate/check as PIResponse object
            $ret = PIResponse::fromJSON($response, $this);
            if ($ret == null)
            {
                $this->debugLog("privacyIDEA - Validate Check: no response from PI-server");
            }
            return $ret;
        } else
        {
            //Handle debug message if $username is empty
            $this->debugLog("privacyIDEA - Validate Check: params incomplete!");
        }
        return null;
    }

    /**
     * Trigger all challenges for the given username.
     * This function requires a service account to be set.
     *
     * @param string $username
     * @return PIResponse|null This method returns an PIResponse object which contains all the useful information from the PI server.
     * @throws PIBadRequestException
     */
    public function triggerChallenge($username)
    {
        assert('string' === gettype($username));

        // Log entry of the pollTransaction()
        $this->debugLog("triggerChallenge() with username=" . $username);

        if ($username)
        {
            $authToken = $this->getAuthToken();
            // If error occurred in getAuthToken() - return this error in PIResponse object
            $header = array("authorization:" . $authToken);

            $parameter = array("user" => $username);

            //Call /validate/triggerchallenge with username as parameter and return it.
            $response = $this->sendRequest($parameter, $header, 'POST', '/validate/triggerchallenge');

            //Return the response from /validate/triggerchallenge as PIResponse object
            $ret = PIResponse::fromJSON($response, $this);

            if ($ret == null)
            {
                $this->debugLog("privacyIDEA - Trigger Challenge: no response from PI-server");
            }
            return $ret;

        } else
        {
            //Handle debug message if empty $username
            $this->debugLog("privacyIDEA - Trigger Challenge: no username");
        }
        return null;
    }

    /**
     * Call /validate/polltransaction using transaction_id
     *
     * @param $transactionID string An unique ID which is needed by some API requests.
     * @return bool Returns true if PUSH is accepted, false otherwise.
     * @throws PIBadRequestException
     */
    public function pollTransaction($transactionID)
    {
        assert('string' === gettype($transactionID));

        // Log entry of the pollTransaction()
        $this->debugLog("pollTransaction() with transaction ID=" . $transactionID);

        if (!empty($transactionID))
        {
            $params = array("transaction_id" => $transactionID);
            // Call /validate/polltransaction using transactionID and decode it from JSON
            $responseJSON = $this->sendRequest($params, array(''), 'GET', '/validate/polltransaction');
            $response = json_decode($responseJSON, true);
            //Return the response from /validate/polltransaction
            return $response['result']['value'];

        } else
        {
            //Handle debug message if $transactionID is empty
            $this->debugLog("privacyIDEA - Poll Transaction: No transaction ID");
        }
        return false;
    }

    /**
     * Check if user already has token
     * Enroll a new token
     *
     * @param string $username
     * @param string $genkey
     * @param string $type
     * @param string $description
     * @return mixed
     * @throws PIBadRequestException
     */
    public function enrollToken($username, $genkey, $type, $description = "") // No return type because mixed not allowed yet
    {
        assert('string' === gettype($username));
        assert('string' === gettype($type));
        assert('string' === gettype($genkey));
        if (isset($description))
        {
            assert('string' === gettype($description));
        }

        // Log entry of the enrollToken()
        $this->debugLog("privacyIDEA - enrollToken() with user=" . $username . ", genkey=" . $genkey . ", type=" . $type . ", description=" . $description);

        // Check if parameters contain the required keys
        if (empty($username) || empty($type))
        {
            $this->debugLog("privacyIDEA - Enroll Token: Token enrollment not possible because params are not complete");
            return array();
        }

        $params["user"] = $username;
        $params["genkey"] = $genkey;
        $params["type"] = $type;
        $params["description"] = in_array("description", $params) ? $description : "";

        $authToken = $this->getAuthToken();

        // If error occurred in getAuthToken() - return this error in PIResponse object
        $header = array("authorization:" . $authToken);

        // Check if user has token
        $tokenInfo = json_decode($this->sendRequest(array("user" => $params['user']), $header, 'GET', '/token/'));

        if (!empty($tokenInfo->result->value->tokens))
        {
            $this->debugLog("privacyIDEA - Enroll Token: User already has a token. No need to enroll a new one.");
            return array();

        } else
        {
            // Call /token/init endpoint and return the PI response
            return json_decode($this->sendRequest($params, $header, 'POST', '/token/init'));
        }
    }

    /**
     * Sends a request to /validate/check with the data required to authenticate a WebAuthn token.
     *
     * @param string $username
     * @param string $transactionID
     * @param string $webAuthnSignResponse
     * @param string $origin
     * @return PIResponse|null
     * @throws PIBadRequestException
     */
    public function validateCheckWebAuthn($username, $transactionID, $webAuthnSignResponse, $origin)
    {
        assert('string' === gettype($username));
        assert('string' === gettype($transactionID));
        assert('string' === gettype($webAuthnSignResponse));
        assert('string' === gettype($origin));

        // Log entry of the validateCheckWebAuthn()
        $this->debugLog("ValidateCheckWebAuthn with user=" . $username . ", transactionID=" . $transactionID . ", WebAuthnSignResponse=" . $webAuthnSignResponse . ", origin=" . $origin);

        // Check if parameters are set
        if (!empty($username) || !empty($transactionID))
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

            $header = array("Origin:" . $origin);

            $response = $this->sendRequest($params, $header, 'POST', '/validate/check');

            //Return the response from /validate/check as PIResponse object
            $ret = PIResponse::fromJSON($response, $this);

            if ($ret == null)
            {
                $this->debugLog("privacyIDEA - WebAuthn: no response from PI-server");
            }
            return $ret;

        } else
        {
            //Handle debug message if $username is empty
            $this->debugLog("privacyIDEA - WebAuthn: params incomplete!");
        }
        return null;
    }

    /**
     * Sends a request to /validate/check with the data required to authenticate a U2F token.
     *
     * @param string $username
     * @param string $transactionID
     * @param string $u2fSignResponse
     * @return PIResponse|null
     * @throws PIBadRequestException
     */
    public function validateCheckU2F($username, $transactionID, $u2fSignResponse)
    {
        assert('string' === gettype($username));
        assert('string' === gettype($transactionID));
        assert('string' === gettype($u2fSignResponse));

        // Log entry of validateCheckU2F
        $this->debugLog("ValidateCheckU2F with user=" . $username . ", transactionID=" . $transactionID . ", u2fSignResponse=" . $u2fSignResponse);

        // Check if parameters are set
        if (!empty($username) || !empty($transactionID) || !empty($u2fSignResponse))
        {

            // Compose standard validate/check params
            $params["user"] = $username;
            $params["pass"] = "";
            $params["transaction_id"] = $transactionID;

            if ($this->realm)
            {
                $params["realm"] = $this->realm;
            }

            // Additional U2F params from $u2fSignResponse
            $tmp = json_decode($u2fSignResponse, true);
            $params[CLIENTDATA] = $tmp["clientData"];
            $params[SIGNATUREDATA] = $tmp["signatureData"];

            $response = $this->sendRequest($params, array(), 'POST', '/validate/check');

            //Return the response from /validate/check as PIResponse object
            $ret = PIResponse::fromJSON($response, $this);

            if ($ret == null)
            {
                $this->debugLog("privacyIDEA - U2F: no response from PI-server");
            }
            return $ret;

        } else
        {
            //Handle debug message if $username is empty
            $this->debugLog("privacyIDEA - U2F: params incomplete!");
        }
        return null;
    }

    /**
     * Check if service account and pass are set
     * @return bool
     */
    public function serviceAccountAvailable()
    {
        return (!empty($this->serviceAccountName) && !empty($this->serviceAccountPass));
    }

    /**
     * Retrieves an auth token from the server using the service account. The auth token is required to make certain requests to privacyIDEA.
     * If no service account is set or an error occurred, this function returns false.
     *
     * @return string|bool|PIResponse the auth token or false.
     * @throws PIBadRequestException
     */
    public function getAuthToken()
    {
        if (!$this->serviceAccountAvailable())
        {
            $this->errorLog("Cannot retrieve auth token without service account");
            return false;
        }

        // To get auth token from server use API Request: /auth with added service account and service pass
        $params = array(
            "username" => $this->serviceAccountName,
            "password" => $this->serviceAccountPass
        );

        if ($this->serviceAccountRealm != null && $this->serviceAccountRealm != "")
        {
            $params["realm"] = $this->serviceAccountRealm;
        }

        // Call /auth endpoint and decode the response from JSON to PHP
        $response = json_decode($this->sendRequest($params, array(''), 'POST', '/auth'), true);

        if (!empty($response['result']['value']))
        {
            // Get auth token from response->result->value->token and return the token
            return $response['result']['value']['token'];
        }

        // If no response return false
        $this->debugLog("privacyIDEA - getAuthToken: No response from PI-Server");
        return false;
    }

    /**
     * Prepare send_request and make curl_init.
     *
     * @param $params array request parameters in an array
     * @param $headers array headers fields in array
     * @param $httpMethod string
     * @param $endpoint string endpoint of the privacyIDEA API (e.g. /validate/check)
     * @return string returns string with response from server or an empty string if error occurs
     * @throws PIBadRequestException
     */
    public function sendRequest(array $params, array $headers, $httpMethod, $endpoint)
    {
        assert('array' === gettype($params));
        assert('array' === gettype($headers));
        assert('string' === gettype($httpMethod));
        assert('string' === gettype($endpoint));

        $this->debugLog("Sending   HEADER: " . http_build_query($headers, '', ', ') . ", with " . $httpMethod . " to " . $endpoint);
        $this->debugLog("And       PARAMS: " . http_build_query($params, '', ', '));

        $curlInstance = curl_init();

        // Compose an API Request using privacyIDEA's URL from config and endpoint created in function
        $completeUrl = $this->serverURL . $endpoint;

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

        } elseif ($httpMethod === "GET")
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

        // Check if you should to verify privacyIDEA's SSL certificate in your config
        // If true - do it, if false - don't verify
        if ($this->sslVerifyHost === true)
        {
            curl_setopt($curlInstance, CURLOPT_SSL_VERIFYHOST, 2);
        } else
        {
            curl_setopt($curlInstance, CURLOPT_SSL_VERIFYHOST, 0);
        }

        if ($this->sslVerifyPeer === true)
        {
            curl_setopt($curlInstance, CURLOPT_SSL_VERIFYPEER, 2);
        } else
        {
            curl_setopt($curlInstance, CURLOPT_SSL_VERIFYPEER, 0);
        }

        //Store response in the variable
        $response = curl_exec($curlInstance);

        if (!$response)
        {
            //Handle error if no response and return an empty string
            $curlErrno = curl_errno($curlInstance);
            $this->errorLog("privacyIDEA-SDK: Bad request to PI server. " . curl_error($curlInstance) . " errno: " . $curlErrno);
            throw new PIBadRequestException("Unable to reach the authentication server (" . $curlErrno . ")");
        }

        $headerSize = curl_getinfo($curlInstance, CURLINFO_HEADER_SIZE);
        $ret = substr($response, $headerSize);

        // Log the response
        if ($endpoint != "/auth")
        {
            $retJson = json_decode($ret, true);
            $this->debugLog($endpoint . " returned " . json_encode($retJson, JSON_PRETTY_PRINT));
        }

        curl_close($curlInstance);

        //Return decoded response from API Request
        return $ret;
    }
}