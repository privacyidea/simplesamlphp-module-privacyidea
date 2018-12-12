<?php
/**
 * This authproc filter enables the possibility to check which IP the client has.
 * If it is wanted, the IDP is able to disable 2FA for special clients.
 * For example a user, which is located in the local area network, does not need 2FA
 * @author Micha Preußer <micha.preusser@netknights.it>
 */

class sspmod_privacyIDEA_Auth_Process_checkClientIP extends SimpleSAML_Auth_ProcessingFilter {

	/**
     * range of excluded IPs
     * enter start and end IP
	 * @var array|mixed
	 */
    private $excludeClientIPs = array();

     public function __construct(array $config, $reserved)
     {
        SimpleSAML_Logger::info("Checking client ip for privacyIDEA");
        parent::__construct($config, $reserved);
        $cfg = SimpleSAML_Configuration::loadFromArray($config, 'privacyidea:checkClientIP');
        $this->excludeClientIPs = $cfg->getArray('excludeClientIPs', null);
     }

	public function process( &$state ) {
        $startIP = ip2long($this->excludeClientIPs[0]);
        $endIP = ip2long($this->excludeClientIPs[1]);
        $clientIP = ip2long($_SERVER['REMOTE_ADDR']);

        if ($clientIP >= $startIP && $clientIP <= $endIP) {
            $state['privacyIDEA']['enabled'][0] = false;
        }

	}

}
