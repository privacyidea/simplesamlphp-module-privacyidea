<?php

/**
 * privacyidea authentication module.
 * 2015-11-21 Cornelius Kölbel <cornelius.koelbel@netknights.it>
 * 	      Add support for U2F authentication requests
 * 2015-11-19 Cornelius Kölbel <cornelius.koelbel@netknights.it>
 *            Add authenticate method to call our own template.
 *            Add handleLogin method to be able to handle challenge response.
 * 2015-11-05 Cornelius Kölbel <cornelius.koelbel@netknights.it>
 *            Revert the authentication logic to avoid false logins
 * 2015-09-23 Cornelius Kölbel <cornelius.koelbel@netknights.it>
 *            Adapt for better usability with
 *	      Univention Corporate Server
 *	      Change Auth Request to POST
 * 2015-04-11 Cornelius Kölbel <cornelius.koelbel@netknights.it>
 *            minor changes by code climate
 * 2014-09-29 Cornelius Kölbel, cornelius@privacyidea.org
 * 
 * This is forked from simplesamlphp-linotp,
 * (https://github.com/lsexperts/simplesamlphp-linotp)
 * which is based on Radius.php
 *
 */
class sspmod_privacyidea_Auth_Source_privacyidea extends sspmod_core_Auth_UserPassBase {

	/**
	 * The URL of the privacyidea server
	 */
	private $privacyideaserver;

	/**
	 * If the sslcert should be checked
	 */
	private $sslverifyhost;

	/**
	 * If the sslcert should be checked
	 */
	private $sslverifypeer;
	
	/**
	 * The realm of the user
	 */
	private $realm;
	
	/**
	 * The attribute map. It is an array
	 */
	 
	private $attributemap = array();
	
	/**
	 * Constructor for this authentication source.
	 *
	 * @param array $info  Information about this authentication source.
	 * @param array $config  Configuration.
	 */
	public function __construct($info, $config) {
		assert('is_array($info)');
		assert('is_array($config)');

		/* Call the parent constructor first, as required by the interface. */
		parent::__construct($info, $config);

		if (array_key_exists('privacyideaserver', $config)) {
			$this->privacyideaserver = $config['privacyideaserver'];
	        }
	        if (array_key_exists('realm', $config)) {
        	    $this->realm = $config['realm'];
	        }
        	if (array_key_exists('sslverifyhost', $config)) {
	            $this->sslverifyhost = $config['sslverifyhost'];
        	}
	        if (array_key_exists('sslverifypeer', $config)) {
        	    $this->sslverifypeer = $config['sslverifypeer'];
	        }
        	if (array_key_exists('attributemap', $config)) {
			$this->attributemap = $config['attributemap'];
		}
		
	}


	/**
	 * Attempt to log in using the given username and password.
	 *
	 * @param string $username  The username the user wrote.
	 * @param string $password  The password the user wrote.
	 * @return array  Associative array with the users attributes.
	 * Each attribute needs to contain a list:
	 * {"uid" => {0 => "Administrator},
	 *  "givenName" => {0 => "Hans",
	 *                  1 => "Dampf"}
	 * }
	 */
	protected function login($username, $password) {
	}

	protected function login_chal_resp($username, $password, $transaction_id, $signaturedata, $clientdata) {
		assert('is_string($username)');
		assert('is_string($password)');
		assert('is_string($transaction_id)');

		$curl_instance = curl_init();
        
		$escPassword = urlencode($password);
		$escUsername = urlencode($username);

		$url = $this->privacyideaserver . '/validate/samlcheck';
		$params = "user=".$escUsername."&pass=".$escPassword."&realm=".urlencode($this->realm);

		if ($transaction_id) {
			SimpleSAML_Logger::debug("Authenticating with transaction_id: ". $transaction_id);
			$params = $params . "&transaction_id=".urlencode($transaction_id);
		}
		if ($signaturedata) {
			SimpleSAML_Logger::debug("Authenticating with signaturedata: ". $signaturedata);
			$params = $params . "&signaturedata=".urlencode($signaturedata);
		}
		if ($clientdata) {
			SimpleSAML_Logger::debug("Authenticating with clientdata: ". $clientdata);
			$params = $params . "&clientdata=".urlencode($clientdata);
		}
		
		//throw new Exception("url: ". $url);
		SimpleSAML_Logger::debug("privacyidea URL:" . $url);
		SimpleSAML_Logger::debug("Params: " . $params);
	
		curl_setopt($curl_instance, CURLOPT_URL, $url);
		curl_setopt($curl_instance, CURLOPT_HEADER, TRUE);
		curl_setopt($curl_instance, CURLOPT_RETURNTRANSFER, TRUE);
		// Add POST params
		curl_setopt($curl_instance, CURLOPT_POST, 3);
		curl_setopt($curl_instance, CURLOPT_POSTFIELDS, $params);

		if ($this->sslverifyhost) {
			curl_setopt($curl_instance, CURLOPT_SSL_VERIFYHOST, 2);
		} else {
			curl_setopt($curl_instance, CURLOPT_SSL_VERIFYHOST, 0);
		}
		if ($this->sslverifypeer) {
			curl_setopt($curl_instance, CURLOPT_SSL_VERIFYPEER, 2);
		} else {
			curl_setopt($curl_instance, CURLOPT_SSL_VERIFYPEER, 0);
		}
	    
		if ( ! $response = curl_exec($curl_instance)){
			throw new SimpleSAML_Error_BadRequest("Bad Request to PI server: " . curl_error($curl_instance));
		};
		$header_size = curl_getinfo($curl_instance,CURLINFO_HEADER_SIZE);
		$body = json_decode(substr( $response, $header_size ));
 
		$status = True;
		$value = False;
		$attributes = NULL;
		$transaction_id = NULL;
    
		try {
			$result = $body->result;
			SimpleSAML_Logger::debug("privacyidea result:" . print_r($result, True));
			$status = $result->status;
			$value = $result->value->auth;
		} catch (Exception $e) {
			throw new SimpleSAML_Error_BadRequest("We were not able to read the response from the privacyidea server.");
		}
		
		if ($status !== True) {
			/* We got a valid JSON respnse, but the STATUS is false */
			throw new SimpleSAML_Error_BadRequest("Valid JSON response, but some internal error occured in privacyidea server.");
		} else {
			/* The STATUS is true, so we need to check the value */
			if ($value !== True) {
				SimpleSAML_Logger::debug("Throwing WRONGUSERPASS");
				$detail = $body->detail;
				$message = $detail->message;
				if (property_exists($detail, "transaction_id")) {
					$transaction_id = $detail->transaction_id;
				}
				if (property_exists($detail, "attributes")) {
					$attributes = $detail->attributes;
					if (property_exists($attributes, "u2fSignRequest")) {
						SimpleSAML_Logger::debug("This is an U2F authentication request");
						SimpleSAML_Logger::debug(print_r($attributes, TRUE));
						/*
						 * In case of U2F the $attributes looks like this:
						[img] => static/css/FIDO-U2F-Security-Key-444x444.png#012
						[hideResponseInput] => 1#012
						[u2fSignRequest] => [challenge] => yji-PL1V0QELilDL3m6Lc-1yahpKZiU-z6ye5Zz2mp8#012
								    [version] => U2F_V2#012
								    [keyHandle] => fxDKTr6o8EEGWPyEyRVDvnoeA0c6v-dgvbN-6Mxc6XBmEItsw#012        
								    [appId] => https://172.16.200.138#012        )#012#012)
						*/
					}
				}
				if ( $transaction_id ) {
					/* If we have a transaction_id, we do challenge response */
					SimpleSAML_Logger::debug("Throwing CHALLENGERESPONSE");
					throw new SimpleSAML_Error_Error(["CHALLENGERESPONSE", $transaction_id, $message, $attributes]);
				}
				SimpleSAML_Logger::debug("Throwing WRONGUSERPASS");
				throw new SimpleSAML_Error_Error("WRONGUSERPASS");
			}
		}

		$user_attributes = $result->value->attributes;
		if (!array_key_exists("username", $user_attributes)) {
			// We have the old response, where the attributes are located directly in the value
			$user_attributes = $result->value;
		}
		SimpleSAML_Logger::debug("privacyidea returned user attributes: " . print_r($user_attributes, True));
		/* status and value are true
		 * We can go on and fill attributes
		 */

		/* If we get this far, we have a valid login. */
		$attributes = array();
		$arr = array( "username", "surname", "email", "givenname", "mobile", "phone", "realm", "resolver");
		reset($arr);
		foreach ( $arr as $key) {
			SimpleSAML_Logger::debug("privacyidea        key: " . $key);
			if (array_key_exists($key, $this->attributemap)) {
				// We have a key mapping
				$mapped_key = $this->attributemap[$key];
				SimpleSAML_Logger::debug("privacyidea mapped key: " . $mapped_key);
				$attribute_value = $user_attributes->$key;
				SimpleSAML_Logger::debug("privacyidea    value  : " . $attribute_value);
				if ($attribute_value) {
					SimpleSAML_Logger::debug("privacyidea Mapped key in response");	
					$attributes[$mapped_key] = array($attribute_value);
					SimpleSAML_Logger::debug("privacyidea      value: " . print_r($attributes[$mapped_key]));
				} 
			} else {
				// We have no keymapping and just transfer the attribute
				SimpleSAML_Logger::debug("privacyidea unmapped key: ". $key);
				if ($user_attributes->$key) {
					$attributes[$key] = array($user_attributes->$key);
					SimpleSAML_Logger::debug("privacyidea        value: ". print_r($attributes[$key]));
				}
			}	
		}
		SimpleSAML_Logger::debug("privacyidea Array returned: " . print_r($attributes, True));
		return $attributes;
	}


        /**
         * Initialize login.
         *
         * This function saves the information about the login, and redirects to a
         * login page.
         *
         * @param array &$state  Information about the current authentication.
         */
        public function authenticate(&$state) {
                assert('is_array($state)');

                /* We are going to need the authId in order to retrieve this authentication source later. */
                $state[self::AUTHID] = $this->authId;
		SimpleSAML_Logger::debug("privacyIDEA authId: ". $this->authId);

                $id = SimpleSAML_Auth_State::saveState($state, self::STAGEID);

                $url = SimpleSAML_Module::getModuleURL('privacyidea/loginform.php');
                SimpleSAML_Utilities::redirectTrustedURL($url, array('AuthState' => $id));
        }

	/**
         * Handle login request.
         *
         * This function is used by the login form (core/www/loginuserpass.php) when the user
         * enters a username and password. On success, it will not return. On wrong
         * username/password failure, and other errors, it will throw an exception.
         *
         * @param string $authStateId  The identifier of the authentication state.
         * @param string $username  The username the user wrote.
         * @param string $password  The password the user wrote.
         */
        public static function handleLogin($authStateId, $username, $password, $transaction_id, $signaturedata, $clientdata) {
                assert('is_string($authStateId)');
                assert('is_string($username)');
                assert('is_string($password)');
		assert('is_string($transaction_id)');

		SimpleSAML_Logger::debug("calling privacyIDEA handleLogin with authState: ". $authStateId . " for user ". $username);

                // sanitize the input
                $sid = SimpleSAML_Utilities::parseStateID($authStateId);
                if (!is_null($sid['url'])) {
                        SimpleSAML_Utilities::checkURLAllowed($sid['url']);
                }

                /* Here we retrieve the state array we saved in the authenticate-function. */
                $state = SimpleSAML_Auth_State::loadState($authStateId, self::STAGEID);

                /* Retrieve the authentication source we are executing. */
                assert('array_key_exists(self::AUTHID, $state)');
                $source = SimpleSAML_Auth_Source::getById($state[self::AUTHID]);
                if ($source === NULL) {
                        throw new Exception('Could not find authentication source with id ' . $state[self::AUTHID]);
                }

                /*
                 * $source now contains the authentication source on which authenticate()
                 * was called. We should call login() on the same authentication source.
                 */

                /* Attempt to log in. */
                try {
                        $attributes = $source->login_chal_resp($username, $password, $transaction_id, $signaturedata, $clientdata);
                } catch (Exception $e) {
                        SimpleSAML_Logger::stats('Unsuccessful login attempt from '.$_SERVER['REMOTE_ADDR'].'.');
                        throw $e;
                }

                SimpleSAML_Logger::stats('User \''.$username.'\' has been successfully authenticated.');

                /* Save the attributes we received from the login-function in the $state-array. */
                assert('is_array($attributes)');
                $state['Attributes'] = $attributes;

                /* Return control to simpleSAMLphp after successful authentication. */
                SimpleSAML_Auth_Source::completeAuth($state);
        }




}
