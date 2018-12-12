<?php
/**
 * If a user does not have a token, a new one could be enrolled.
 * @author Micha Preußer <micha.preusser@netknights.it>
 */

class sspmod_privacyIDEA_Auth_Process_tokenEnrollment extends SimpleSAML_Auth_ProcessingFilter {

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
	}

	public function process( &$state) {
		
	}

}