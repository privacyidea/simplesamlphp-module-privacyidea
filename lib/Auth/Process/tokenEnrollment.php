<?php
/**
 * If a user does not have a token, a new one could be enrolled.
 * This one will be generated with a QR-code, which can be scanned with a mobile device.
 * For that you'll need an application like 'privacyIDEA Authenticator' or 'Google Authenticator'
 * @author Micha Preußer <micha.preusser@netknights.it>
 */

class sspmod_privacyIDEA_Auth_Process_tokenEnrollment extends SimpleSAML_Auth_ProcessingFilter {

	/**
	 *
	 */
	private $privacyIDEA_URL;

	/**
	 * The administrator has to configure which token type the user should enroll.
	 * @var String
	 */
	private $tokenType;

	/**
	 * The username for the service account
	 * @var String
	 */
	private $serviceAccount;

	/**
	 * The password for the service account
	 * @var String
	 */
	private $servicePass;

	private $token;

	private $sslverifyhost;
	private $sslverifypeer;
	private $uidKey;

	public function __construct( array $config, $reserved ) {
		parent::__construct( $config, $reserved );
		$cfg = SimpleSAML_Configuration::loadFromArray($config, 'privacyidea:tokenEnrollment');
		$this->tokenType = $cfg->getString('tokenType', 'totp');
		$this->serviceAccount = $cfg->getString('serviceAccount', 'service');
		$this->servicePass = $cfg->getString('servicePass', 'service');

		$cfg = SimpleSAML_Configuration::loadFromArray($config, 'privacyidea:privacyidea');
		$this->privacyIDEA_URL = $cfg->getString('privacyideaserver', 'https://appliance1.intranet.de');
		$this->sslverifyhost = $cfg->getBoolean('sslverifyhost', false);
		$this->sslverifypeer = $cfg->getBoolean('sslverifypeer', false);
		$this->uidKey = $cfg->getString('uidKey', 'uid');
	}

	public function process( &$state ) {
		$this->token = $this->fetchAuthToken();
		if (!$this->userHasToken($state)) {
			$state['privaycidea:tokenEnrollment:tokenQR'] = $this->enrollToken($state);
		}
	}

	public function enrollToken ( &$state ) {

		$curl_instance = curl_init();
		$params        = array(
			"user" => $state["Attributes"][$this->uidKey][0],
			"genkey" => 1,
			"type" => $this->tokenType,
		);
		$headers = array(
			"authorization: " . $this->token,
		);

		$url = $this->privacyIDEA_URL . "/token/init";

		curl_setopt( $curl_instance, CURLOPT_URL, $url );
		curl_setopt( $curl_instance, CURLOPT_HEADER, true );
		curl_setopt( $curl_instance, CURLOPT_HTTPHEADER, $headers);
		curl_setopt( $curl_instance, CURLOPT_RETURNTRANSFER, true );
		curl_setopt( $curl_instance, CURLOPT_USERAGENT, "simpleSAMLphp" );
		// Add POST params
		curl_setopt( $curl_instance, CURLOPT_POST, 3 );
		curl_setopt( $curl_instance, CURLOPT_POSTFIELDS, $params );

		if ( $this->sslverifyhost ) {
			curl_setopt( $curl_instance, CURLOPT_SSL_VERIFYHOST, 2 );
		} else {
			curl_setopt( $curl_instance, CURLOPT_SSL_VERIFYHOST, 0 );
		}
		if ( $this->sslverifypeer ) {
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
			"user" => $state["Attributes"][$this->uidKey][0],
		);
		$headers = array(
			"authorization: " . $this->token,
		);

		$url = $this->privacyIDEA_URL . "/token/?";

		curl_setopt( $curl_instance, CURLOPT_URL, $url . $params );
		curl_setopt( $curl_instance, CURLOPT_HEADER, true );
		curl_setopt( $curl_instance, CURLOPT_HTTPHEADER, $headers);
		curl_setopt( $curl_instance, CURLOPT_RETURNTRANSFER, true );
		curl_setopt( $curl_instance, CURLOPT_USERAGENT, "simpleSAMLphp" );
		if ( $this->sslverifyhost ) {
			curl_setopt( $curl_instance, CURLOPT_SSL_VERIFYHOST, 2 );
		} else {
			curl_setopt( $curl_instance, CURLOPT_SSL_VERIFYHOST, 0 );
		}
		if ( $this->sslverifypeer ) {
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
			"username" => $this->serviceAccount,
			"password" => $this->servicePass,
		);

		$url = $this->privacyIDEA_URL . "/auth";

		curl_setopt( $curl_instance, CURLOPT_URL, $url );
		curl_setopt( $curl_instance, CURLOPT_HEADER, true );
		curl_setopt( $curl_instance, CURLOPT_RETURNTRANSFER, true );
		curl_setopt( $curl_instance, CURLOPT_USERAGENT, "simpleSAMLphp" );
		// Add POST params
		curl_setopt( $curl_instance, CURLOPT_POST, 3 );
		curl_setopt( $curl_instance, CURLOPT_POSTFIELDS, $params );

		if ( $this->sslverifyhost ) {
			curl_setopt( $curl_instance, CURLOPT_SSL_VERIFYHOST, 2 );
		} else {
			curl_setopt( $curl_instance, CURLOPT_SSL_VERIFYHOST, 0 );
		}
		if ( $this->sslverifypeer ) {
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