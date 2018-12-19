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

		$curl_instance = curl_init();
		$params        = array(
			"user" => $state["Attributes"][$this->serverconfig['uidKey']][0],
			"genkey" => 1,
			"type" => $this->serverconfig['tokenType'],
		);
		$headers = array(
			"authorization: " . $this->auth_token,
		);

		$url = $this->serverconfig['privacyideaserver'] . "/token/init";

		curl_setopt( $curl_instance, CURLOPT_URL, $url );
		curl_setopt( $curl_instance, CURLOPT_HEADER, true );
		curl_setopt( $curl_instance, CURLOPT_HTTPHEADER, $headers);
		curl_setopt( $curl_instance, CURLOPT_RETURNTRANSFER, true );
		curl_setopt( $curl_instance, CURLOPT_USERAGENT, "simpleSAMLphp" );
		// Add POST params
		curl_setopt( $curl_instance, CURLOPT_POST, 3 );
		curl_setopt( $curl_instance, CURLOPT_POSTFIELDS, $params );

		if ( $this->serverconfig['sslverifyhost'] ) {
			curl_setopt( $curl_instance, CURLOPT_SSL_VERIFYHOST, 2 );
		} else {
			curl_setopt( $curl_instance, CURLOPT_SSL_VERIFYHOST, 0 );
		}
		if ( $this->serverconfig['sslverifypeer'] ) {
			curl_setopt( $curl_instance, CURLOPT_SSL_VERIFYPEER, 2 );
		} else {
			curl_setopt( $curl_instance, CURLOPT_SSL_VERIFYPEER, 0 );
		}
		if ( ! $response = curl_exec( $curl_instance ) ) {
			throw new SimpleSAML_Error_BadRequest( "privacyIDEA: Bad request to PI server: " . curl_error( $curl_instance ) );
		};
		$header_size = curl_getinfo( $curl_instance, CURLINFO_HEADER_SIZE );
		$body = json_decode( substr( $response, $header_size ) );
		try {
			$detail = $body->detail;
			$googleurl = $detail->googleurl;
			$img = $googleurl->img;
		} catch ( Exception $e ) {
			throw new SimpleSAML_Error_BadRequest( "privacyIDEA: We were not able to read the response from the PI server" );
		}
		return $img;


	}

	public function userHasToken( &$state ) {

		$curl_instance = curl_init();
		$params = array(
			"user" => $state["Attributes"][$this->serverconfig['uidKey']][0],
		);
		$headers = array(
			"authorization: " . $this->auth_token,
		);

		$url = $this->serverconfig['privacyideaserver'] . "/token/?";

		curl_setopt( $curl_instance, CURLOPT_URL, $url . $params );
		curl_setopt( $curl_instance, CURLOPT_HEADER, true );
		curl_setopt( $curl_instance, CURLOPT_HTTPHEADER, $headers);
		curl_setopt( $curl_instance, CURLOPT_RETURNTRANSFER, true );
		curl_setopt( $curl_instance, CURLOPT_USERAGENT, "simpleSAMLphp" );
		if ( $this->serverconfig['sslverifyhost'] ) {
			curl_setopt( $curl_instance, CURLOPT_SSL_VERIFYHOST, 2 );
		} else {
			curl_setopt( $curl_instance, CURLOPT_SSL_VERIFYHOST, 0 );
		}
		if ( $this->serverconfig['sslverifypeer'] ) {
			curl_setopt( $curl_instance, CURLOPT_SSL_VERIFYPEER, 2 );
		} else {
			curl_setopt( $curl_instance, CURLOPT_SSL_VERIFYPEER, 0 );
		}
		if ( ! $response = curl_exec( $curl_instance ) ) {
			throw new SimpleSAML_Error_BadRequest( "privacyIDEA: Bad request to PI server: " . curl_error( $curl_instance ) );
		};
	    SimpleSAML_Logger::debug("privacyIDEA: \n\n\n" . $response . "\n\n\n");
		$header_size = curl_getinfo( $curl_instance, CURLINFO_HEADER_SIZE );
		$body = json_decode( substr( $response, $header_size ) );
		try {
			$result = $body->result;
			$value = $result->value;
			$count = $value->count;
		} catch ( Exception $e ) {
			throw new SimpleSAML_Error_BadRequest( "privacyIDEA: We were not able to read the response from the PI server" );
		}
		if ($count == 0) {
			return false;
		} else {
			SimpleSAML_Logger::debug("privacyIDEA: user has" . $count . " tokens.");
			return true;
		}

	}

	public function fetchAuthToken() {

		$curl_instance = curl_init();
		$params        = array(
			"username" => $this->serverconfig['serviceAccount'],
			"password" => $this->serverconfig['servicePass'],
		);

		$url = $this->serverconfig['privacyideaserver'] . "/auth";

		curl_setopt( $curl_instance, CURLOPT_URL, $url );
		curl_setopt( $curl_instance, CURLOPT_HEADER, true );
		curl_setopt( $curl_instance, CURLOPT_RETURNTRANSFER, true );
		curl_setopt( $curl_instance, CURLOPT_USERAGENT, "simpleSAMLphp" );
		// Add POST params
		curl_setopt( $curl_instance, CURLOPT_POST, 3 );
		curl_setopt( $curl_instance, CURLOPT_POSTFIELDS, $params );

		if ( $this->serverconfig['sslverifyhost'] ) {
			curl_setopt( $curl_instance, CURLOPT_SSL_VERIFYHOST, 2 );
		} else {
			curl_setopt( $curl_instance, CURLOPT_SSL_VERIFYHOST, 0 );
		}
		if ( $this->serverconfig['sslverifypeer'] ) {
			curl_setopt( $curl_instance, CURLOPT_SSL_VERIFYPEER, 2 );
		} else {
			curl_setopt( $curl_instance, CURLOPT_SSL_VERIFYPEER, 0 );
		}
		if ( ! $response = curl_exec( $curl_instance ) ) {
			throw new SimpleSAML_Error_BadRequest( "privacyIDEA: Bad request to PI server: " . curl_error( $curl_instance ) );
		};
		$header_size = curl_getinfo( $curl_instance, CURLINFO_HEADER_SIZE );
		$body = json_decode( substr( $response, $header_size ) );
		try {
			$result = $body->result;
			$value = $result->value;
			$token = $value->token;
		} catch ( Exception $e ) {
			throw new SimpleSAML_Error_BadRequest( "privacyIDEA: We were not able to read the response from the PI server" );
		}
		return $token;

	}
}