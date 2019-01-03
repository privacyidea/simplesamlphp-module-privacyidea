<?php
/**
 * If a user does not have a token, a new one could be enrolled.
 * This one will be generated with a QR-code, which can be scanned with a mobile device.
 * For that you'll need an application like 'privacyIDEA Authenticator' or 'Google Authenticator'
 * @author Micha Preußer <micha.preusser@netknights.it>
 */

class sspmod_privacyIDEA_Auth_Process_tokenEnrollment extends SimpleSAML_Auth_ProcessingFilter {

	/**
	 * This is the token, which will be fetched by the service account.
	 * It is needed to get the number of tokens and to enroll one.
	 * @var String
	 */
	private $auth_token;

	/**
	 * This contains the server configuration
	 * @var array
	 */
	private $serverconfig;

	public function __construct( array $config, $reserved ) {
		parent::__construct( $config, $reserved );
		$cfg = SimpleSAML_Configuration::loadFromArray($config, 'privacyidea:tokenEnrollment');
        $this->serverconfig['privacyideaserver'] = $cfg->getString('privacyideaserver', null);
        $this->serverconfig['sslverifyhost'] = $cfg->getBoolean('sslverifyhost', null);
        $this->serverconfig['sslverifypeer'] = $cfg->getBoolean('sslverifypeer', null);
        $this->serverconfig['realm'] = $cfg->getString('realm', null);
        $this->serverconfig['uidKey'] = $cfg->getString('uidKey', null);
        $this->serverconfig['enabledPath'] = $cfg->getString('enabledPath', null);
        $this->serverconfig['enabledKey'] = $cfg->getString('enabledKey', null);
        $this->serverconfig['serviceAccount'] = $cfg->getString('serviceAccount', null);
	    $this->serverconfig['servicePass'] = $cfg->getString('servicePass', null);
	    $this->serverconfig['tokenType'] = $cfg->getString('tokenType', 'totp');
	}

	public function process( &$state ) {

		foreach ($this->serverconfig as $key => $value) {
	    	if ($value === null) {
	    		$this->serverconfig[$key] = $state['privacyidea:serverconfig'][$key];
		    }
	    }

		if(isset($state[$this->serverconfig['enabledPath']][$this->serverconfig['enabledKey']][0])) {
			$piEnabled = $state[$this->serverconfig['enabledPath']][$this->serverconfig['enabledKey']][0];
		} else {
			$piEnabled = True;
		}

		if ($this->serverconfig['serviceAccount'] === null or $this->serverconfig['servicePass'] === null) {
			$piEnabled = False;
			SimpleSAML_Logger::error("privacyIDEA service account for token enrollment is not set!");
		}

		if ($this->serverconfig['privacyideaserver'] === null) {
			$piEnabled = False;
			SimpleSAML_Logger::error("privacyIDEA url is not set!");
		}

		if ($piEnabled) {
			$this->auth_token = $this->fetchAuthToken();
			if (!$this->userHasToken($state)) {
				$state['privacyidea:tokenEnrollment']['tokenQR'] = $this->enrollToken($state);
			}
		}
	}

	public function enrollToken ( &$state ) {

		$params        = array(
			"user" => $state["Attributes"][$this->serverconfig['uidKey']][0],
			"genkey" => 1,
			"type" => $this->serverconfig['tokenType'],
		);
		$headers = array(
			"authorization: " . $this->auth_token,
		);

		$body = sspmod_privacyidea_Auth_utils::curl($params, $headers, $this->serverconfig, "/token/init", true);
		try {
			$detail = $body->detail;
			$googleurl = $detail->googleurl;
			$img = $googleurl->img;
		} catch (Exception $e) {
			throw new SimpleSAML_Error_BadRequest("privacyIDEA: We were not able to read the response from the PI server");
		}
		return $img;


	}

	public function userHasToken( &$state ) {

		$params = array(
			"user" => $state["Attributes"][$this->serverconfig['uidKey']][0],
		);
		$headers = array(
			"authorization: " . $this->auth_token,
		);

		$body = sspmod_privacyidea_Auth_utils::curl($params, $headers, $this->serverconfig, "/token/?", false);
		try {
			$result = $body->result;
			$value  = $result->value;
			$count  = $value->count;
		} catch (Exception $e) {
			throw new SimpleSAML_Error_BadRequest("privacyIDEA: We were not able to read the response from the PI server");
		}
		if ($count == 0) {
			return false;
		} else {
			return true;
		}
	}

	public function fetchAuthToken() {

		$params = array(
			"username" => $this->serverconfig['serviceAccount'],
			"password" => $this->serverconfig['servicePass'],
		);

		$body = sspmod_privacyidea_Auth_utils::curl($params, null, $this->serverconfig, "/auth", true);
		try {
			$result = $body->result;
			$value  = $result->value;
			$token  = $value->token;
		} catch (Exception $e) {
			throw new SimpleSAML_Error_BadRequest("privacyIDEA: We were not able to read the response from the PI server");
		}
		return $token;
	}
}