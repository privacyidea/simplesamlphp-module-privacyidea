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
	    $this->serverconfig['tryFirstAuthentication'] = $cfg->getBoolean('tryFirstAuthentication', null);
	    $this->serverconfig['tryFirstAuthPass'] = $cfg->getString('tryFirstAuthPass', null);
	    $this->serverconfig['SSO'] = $cfg->getBoolean('SSO', null);
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

        /**
         * skip privacyIDEA for authenticated users in passive requests and if SSO is enabled
         * if $state["Expire"] is set, the user was already authenticated prior to the present
         * request
         */
        if (isset($state['isPassive']) && $state['isPassive'] === true) {
            if (isset($state["Expire"]) && $state["Expire"] > time()) {
                SimpleSAML_Logger::debug("privacyIDEA: ignoring passive SAML request for already logged in user");
                return;
            }
            throw new \SimpleSAML\Module\saml\Error\NoPassive('Passive authentication (OTP) not supported.');
        }
        if (isset($this->serverconfig['SSO']) && $this->serverconfig['SSO'] === true) {
            if (isset($state["Expire"]) && $state["Expire"] > time()) {
                SimpleSAML_Logger::debug("privacyIDEA: SSO is enabled. Ignoring SAML request for already logged in user.");
                return;
            }
        }

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
			if ($this->serverconfig['tryFirstAuthentication']) {
				try {
					if ($this->authenticate($state, $this->serverconfig['tryFirstAuthPass'], null, null, null, null)) {
						return;
					}
				} catch (SimpleSAML_Error_Error $e) {
					SimpleSAML_Logger::debug("privacyIDEA: user has token");
				}
			}
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
				$state = sspmod_privacyidea_Auth_utils::checkTokenType($state, $body);
			}
			SimpleSAML_Logger::debug("privacyIDEA: privacyIDEA is enabled, so we use 2FA");
			$state['privacyidea:privacyidea:authenticationMethod'] = "authprocess";
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

    public static function authenticate(array &$state, $otp, $transaction_id, $signaturedata, $clientdata, $registrationdata)
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
        if ($registrationdata) {
        	SimpleSAML_Logger::debug("Authenticating with regdata: " . urlencode($registrationdata));
        	$params["regdata"] = $registrationdata;
        }
        $multi_challenge = NULL;

        if (isset($state['privacyidea:tokenEnrollment']['enrollU2F']) && $transaction_id) {
        	$params['type'] = "u2f";
        	$params['description'] = "Enrolled with simpleSAMLphp";
        	$params['serial'] = $state['privacyidea:tokenEnrollment']['serial'];
        	$authToken = $state['privacyidea:tokenEnrollment']['authToken'];
        	$headers = array(
		        "authorization: " . $authToken,
	        );
        	$body = sspmod_privacyidea_Auth_utils::curl($params, $headers, $cfg, "/token/init", "POST");
        	return true;
        }
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
		    if (property_exists($body, "detail")) {
				$detail = $body->detail;
				if (property_exists($detail, "multi_challenge")) {

					$state = sspmod_privacyidea_Auth_utils::checkTokenType($state, $body);

					SimpleSAML_Logger::debug("privacyIDEA: privacyIDEA is enabled, so we use 2FA");
					$id  = SimpleSAML_Auth_State::saveState( $state, 'privacyidea:privacyidea:init' );
					$url = SimpleSAML_Module::getModuleURL( 'privacyidea/otpform.php' );
					SimpleSAML_Utilities::redirectTrustedURL( $url, array( 'StateId' => $id ) );
					return true;
				}
				else {
					SimpleSAML_Logger::error("privacyIDEA WRONG USER PASSWORD");
					throw new SimpleSAML_Error_Error("WRONGUSERPASS");
				}
			} else {
				throw new SimpleSAML_Error_Error("WRONGUSERPASS");
			}
		}

	    SimpleSAML_Logger::debug( "privacyIDEA: User authenticated successfully" );
	    return true;
    }

}
