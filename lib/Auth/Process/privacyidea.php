<?php
/**
 * This authentication processing filter allows you to add a second step
 * authentication against privacyIDEA
 *
 * @author Cornelius Kölbel <cornelius.koelbel@netknights.it>
 */



class sspmod_privacyidea_Auth_Process_privacyidea extends SimpleSAML_Auth_ProcessingFilter
{
	/**
	 * This contains the server configuration
	 * @var array
	 */
	private $serverconfig;

    /**
     * privacyidea constructor.
     *
     * @param array $config The configuration of this authproc.
     * @param mixed $reserved
     *
     * @throws \SimpleSAML\Error\CriticalConfigurationError in case the configuration is wrong.
     */

     public function __construct(array $config, $reserved)
     {
        SimpleSAML_Logger::info("Create the Auth Proc Filter privacyidea");
        parent::__construct($config, $reserved);
        $cfg = SimpleSAML_Configuration::loadFromArray($config, 'privacyidea:privacyidea');
        $this->serverconfig['privacyideaserver'] = $cfg->getString('privacyideaserver', null);
        $this->serverconfig['sslverifyhost'] = $cfg->getBoolean('sslverifyhost', null);
        $this->serverconfig['sslverifypeer'] = $cfg->getBoolean('sslverifypeer', null);
        $this->serverconfig['realm'] = $cfg->getString('realm', null);
         try {
             $this->serverconfig['uidKey'] = array($cfg->getString('uidKey'));
         } catch (Exception $e) {
             $this->serverconfig['uidKey'] = $cfg->getArray('uidKey', null);
         }
        $this->serverconfig['enabledPath'] = $cfg->getString('enabledPath', null);
        $this->serverconfig['enabledKey'] = $cfg->getString('enabledKey', null);
        $this->serverconfig['serviceAccount'] = $cfg->getString('serviceAccount', null);
	    $this->serverconfig['servicePass'] = $cfg->getString('servicePass', null);
	    $this->serverconfig['doTriggerChallenge'] = $cfg->getBoolean('doTriggerChallenge', null);
     }

    /**
     * Run the filter.
     *
     * @param array $state
     *
     * @throws \Exception if authentication fails
     */
    public function process(&$state)
    {
	    SimpleSAML_Logger::info("privacyIDEA Auth Proc Filter: Entering process function");

	    /**
	     * If a configuration is not set in privacyidea:tokenEnrollment,
	     * We are using the config from privacyidea:serverconfig.
	     */

	    if (!empty($this->serverconfig['uidKey'])) {
            foreach ($this->serverconfig['uidKey'] as $uidKey) {
                if (isset($state['Attributes'][$uidKey][0])) {
                    $this->serverconfig['uidKey'] = $uidKey;
                    break;
                }
            }
        }

	    foreach ($this->serverconfig as $key => $value) {
	    	if ($value === null) {
	    		$this->serverconfig[$key] = $state['privacyidea:serverconfig'][$key];
		    }
	    }

    	$state['privacyidea:privacyidea'] = array(
    		'privacyideaserver' => $this->serverconfig['privacyideaserver'],
		    'sslverifyhost' => $this->serverconfig['sslverifyhost'],
		    'sslverifypeer' => $this->serverconfig['sslverifypeer'],
		    'realm' => $this->serverconfig['realm'],
		    'uidKey' => $this->serverconfig['uidKey'],
	    );

    	if(isset($state[$this->serverconfig['enabledPath']][$this->serverconfig['enabledKey']][0])) {
    		$piEnabled = $state[$this->serverconfig['enabledPath']][$this->serverconfig['enabledKey']][0];
	    } else {
    		$piEnabled = True;
	    }

		if ($this->serverconfig['privacyideaserver'] === '') {
			$piEnabled = False;
			SimpleSAML_Logger::error("privacyIDEA url is not set!");
		}

		if($piEnabled) {
			if ($this->serverconfig['doTriggerChallenge']) {
				$authToken = sspmod_privacyidea_Auth_utils::fetchAuthToken($this->serverconfig);
				$params = array(
					"user" => $state["Attributes"][$this->serverconfig['uidKey']][0],
				);
				$headers = array(
					"authorization:" . $authToken,
				);
				$body = sspmod_privacyidea_Auth_utils::curl($params, $headers, $this->serverconfig, "/validate/triggerchallenge", "POST");
				try {
					$detail = $body->detail;
					$multi_challenge = $detail->multi_challenge;
				} catch (Exception $e) {
					throw new SimpleSAML_Error_BadRequest("privacyIDEA: We were not able to read the response from the PI server");
				}
				$use_u2f = false;
				$use_otp = false;
				for ($i = 0; $i < count($multi_challenge); $i++) {
					if ($multi_challenge[$i]->type === "u2f") {
						$use_u2f = true;
					} else {
						$use_otp = true;
					}
				}
				if ($use_u2f === true) {
					SimpleSAML_Logger::debug("privacyIDEA: The user has u2f token");
					$state['privacyidea:privacyidea:doTriggerChallenge'] = array(
						"transaction_id" => $detail->transaction_id,
						"multi_challenge" => $multi_challenge,
					);
				}
				if ($use_otp === true) {
					SimpleSAML_Logger::debug("privacyIDEA: The user has otp token");
				}
				$state['privacyidea:privacyidea:doTriggerChallenge']['use_u2f'] = $use_u2f;
				$state['privacyidea:privacyidea:doTriggerChallenge']['use_otp'] = $use_otp;
			}
			SimpleSAML_Logger::debug("privacyIDEA: privacyIDEA is enabled, so we use 2FA");
			$id  = SimpleSAML_Auth_State::saveState( $state, 'privacyidea:privacyidea:init' );
			$url = SimpleSAML_Module::getModuleURL( 'privacyidea/otpform.php' );
			SimpleSAML_Utilities::redirectTrustedURL( $url, array( 'StateId' => $id ) );
		} else {
			SimpleSAML_Logger::debug("privacyIDEA: " . $this->serverconfig['enabledPath'] . " -> " . $this->serverconfig['enabledKey'] . " is not set to true -> privacyIDEA is disabled");
		}
    }

    /**
     * Perform 2FA authentication given the current state and an OTP from a token managed by privacyIDEA
     * The otp is sent to the privacyidea_url.
     *
     * @param array $state The state array in the "privacyidea:privacyidea:init" stage.
     * @param string $otp A one time password generated by a yubikey.
     * @return boolean True if authentication succeeded and the key belongs to the user, false otherwise.
     *
     * @throws \InvalidArgumentException if the state array is not in a valid stage or the given OTP has incorrect
     * length.
     */

    public static function authenticate(array &$state, $otp, $transaction_id, $signaturedata, $clientdata)
    {

	    $cfg = $state['privacyidea:privacyidea'];

	    $params = array(
		    "user" => $state["Attributes"][$cfg['uidKey']][0],
		    "pass" => $otp,
		    "realm"=> $cfg['realm'],
	    );
        if ($transaction_id) {
            SimpleSAML_Logger::debug("Authenticating with transaction_id: " . $transaction_id);
            $params["transaction_id"] = $transaction_id;
        }
        if ($signaturedata) {
            SimpleSAML_Logger::debug("Authenticating with signaturedata: " . urlencode($signaturedata));
            $params["signaturedata"] = $signaturedata;
        }
        if ($clientdata) {
            SimpleSAML_Logger::debug("Authenticating with clientdata: " . urlencode($clientdata));
            $params["clientdata"] = $clientdata;
        }
        $multi_challenge = NULL;

	    $body = sspmod_privacyidea_Auth_utils::curl($params, null, $cfg, "/validate/samlcheck", "POST");

	    try {
		    $result = $body->result;
		    $status = $result->status;
		    $value  = $result->value;
		    $auth   = $value->auth;
	    } catch (Exception $e) {
		    throw new SimpleSAML_Error_BadRequest("privacyIDEA: We were not able to read the response from the PI server");
	    }

	    if ($status !== true) {
		    throw new SimpleSAML_Error_BadRequest("privacyIDEA: Valid JSON response, but some internal error occured in PI server");
	    }
	    if ( $auth !== true ) {
		    SimpleSAML_Logger::debug( "Throwing WRONGUSERPASS" );
		    $detail = $body->detail;
		    if (property_exists($detail, "multi_challenge")) {
		    	$multi_challenge = $detail->multi_challenge;
		    }
		    if (property_exists($detail, "transaction_id")){
		    	$transaction_id = $detail->transaction_id;
			    /* If we have a transaction_id, we do challenge response */
			    SimpleSAML_Logger::debug( "Throwing CHALLENGERESPONSE" );
			    throw new SimpleSAML_Error_Error(array("CHALLENGERESPONSE", $transaction_id, $multi_challenge));
		    }
		    SimpleSAML_Logger::debug( "Throwing WRONGUSERPASS" );
		    throw new SimpleSAML_Error_Error( "WRONGUSERPASS" );
		}

	    SimpleSAML_Logger::debug( "privacyIDEA: User authenticated successfully" );
	    return true;
    }

}
