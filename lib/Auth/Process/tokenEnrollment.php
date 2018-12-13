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

	public function __construct( array $config, $reserved ) {
		parent::__construct( $config, $reserved );
		$cfg = SimpleSAML_Configuration::loadFromArray($config, 'privacyidea:tokenEnrollment');
		$this->tokenType = $cfg->getString('tokenType', 'totp');
		$this->serviceAccount = $cfg->getString('serviceAccount', 'service');
		$this->servicePass = $cfg->getString('servicePass', 'service');

		$cfg = SimpleSAML_Configuration::loadFromArray($config, 'privacyidea:privacyidea');
		$this->privacyIDEA_URL = $cfg->getString('privacyideaserver');
	}

	public function process( &$state ) {
		
	}

	public function checkIfUserHasToken( &$state ) {

	}

}