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

	/**
	 * This is the token, which will be fetched by the service account.
	 * It is needed to get the number of tokens and to enroll one.
	 * @var String
	 */
	private $auth_token;

	/**
	 * Check if the hostname matches the name in the certificate
	 * @var boolean
	 */
	private $sslverifyhost;

	/**
	 * Check if the certificate is valid, signed by a trusted CA
	 * @var boolean
	 */
	private $sslverifypeer;

	/**
	 * The key where the username is stored (must be under Attributes)
	 * @var string
	 */
	private $uidKey;

	/**
	 * If another authproc filter should be able to turn on or off privacyIDEA, the path to the key be entered here.
	 * @var string
	 */
	private $enabledPath;

	/**
	 * The location for the key to enable or disable 2FA with privacyIDEA.
	 * @var string
	 */
	private $enabledKey;

	public function __construct( array $config, $reserved ) {
		parent::__construct( $config, $reserved );
		$cfg = SimpleSAML_Configuration::loadFromArray($config, 'privacyidea:tokenEnrollment');
		$this->tokenType = $cfg->getString('tokenType', 'totp');
		$this->serviceAccount = $cfg->getString('serviceAccount', '');
		$this->servicePass = $cfg->getString('servicePass', '');
	}

	public function process( &$state ) {
		$this->privacyIDEA_URL = $state['privacyidea:serverconfig']['privacyIDEA_URL'];
		$this->sslverifyhost = $state['privacyidea:serverconfig']['sslverifyhost'];
		$this->sslverifypeer = $state['privacyidea:serverconfig']['sslverifypeer'];
		$this->uidKey = $state['privacyidea:serverconfig']['uidKey'];
		$this->enabledPath = $state['privacyidea:serverconfig']['enabledPath'];
		$this->enabledKey = $state['privacyidea:serverconfig']['enabledKey'];


		if(isset($state[$this->enabledPath][$this->enabledKey][0])) {
			$piEnabled = $state[$this->enabledPath][$this->enabledKey][0];
		} else {
			$piEnabled = True;
		}

		if ($this->serviceAccount === '' or $this->servicePass === '') {
			$piEnabled = False;
			SimpleSAML_Logger::error("privacyIDEA service account for token enrollment is not set!");
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
			"user" => $state["Attributes"][$this->uidKey][0],
			"genkey" => 1,
			"type" => $this->tokenType,
		);
		$headers = array(
			"authorization: " . $this->auth_token,
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
			"authorization: " . $this->auth_token,
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