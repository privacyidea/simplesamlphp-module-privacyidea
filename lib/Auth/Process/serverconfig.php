<?php
/**
 * This authproc filter reads the configuration for the privacyidea server.
 * @author Micha Preußer <micha.preusser@netknights.it>
 */

class sspmod_privacyidea_Auth_Process_serverconfig extends SimpleSAML_Auth_ProcessingFilter {

	/**
	 * The url of the privacyIDEA system
	 * @var string
	 */
	private $privacyIDEA_URL;

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
	 * The realm where the user is located in
	 * @var string
	 */
	private $realm;

	/**
	 * The key where the username is stored (must be under Attributes)
	 * @var string
	 */
	private $uidKey;

	public function __construct( array $config, $reserved ) {

		parent::__construct( $config, $reserved );
		$cfg = SimpleSAML_Configuration::loadFromArray($config, 'privacyidea:serverconfig');
		$this->privacyIDEA_URL = $cfg->getString('privacyideaserver');
		$this->sslverifyhost = $cfg->getBoolean('sslverifyhost', true);
		$this->sslverifypeer = $cfg->getBoolean('sslverifypeer', true);
		$this->realm = $cfg->getString('realm', '');
		$this->uidKey = $cfg->getString('uidKey', 'uid');
	}

	public function process( &$state ) {

		$state['privacyidea:serverconfig'] = array(
    		'privacyIDEA_URL' => $this->privacyIDEA_URL,
		    'sslverifyhost' => $this->sslverifyhost,
		    'sslverifypeer' => $this->sslverifypeer,
		    'realm' => $this->realm,
		    'uidKey' => $this->uidKey,
		);
	}
}