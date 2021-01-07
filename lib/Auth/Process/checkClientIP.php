<?php
/**
 * This Auth Proc Filter allows to check the IP of the client and to control the 
 * two-factor authentication of the following privacyIDEA Auth Proc Filter depending on the client IP.
 * For example, it can be used to configure that a user does not need to provide a 
 * second factor when logging in from the local network.
 * @author Micha Preußer <micha.preusser@netknights.it>
 */

class sspmod_privacyidea_Auth_Process_checkClientIP extends SimpleSAML_Auth_ProcessingFilter {

	/**
	 * enter excluded ip addresses
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
		$clientIP = ip2long($this->getClientIP());
		$piEnabled = true;
		foreach ( $this->excludeClientIPs as $ipAddress ) {
			if (strpos($ipAddress, '-') !== false) {
				$range = explode('-', $ipAddress);
				$startIP = ip2long($range[0]);
				$endIP = ip2long($range[1]);
				if ($clientIP >= $startIP && $clientIP <= $endIP) {
					$piEnabled = false;
				}
			} else {
				if ($clientIP == ip2long($ipAddress)) {
					$piEnabled = false;
				}
			}
     	}
		$state['privacyIDEA']['enabled'][0] = $piEnabled;

	}

	public function getClientIP(){
		if (array_key_exists('HTTP_X_FORWARDED_FOR', $_SERVER)){
			return  $_SERVER["HTTP_X_FORWARDED_FOR"];
		}else if (array_key_exists('REMOTE_ADDR', $_SERVER)) {
			return $_SERVER["REMOTE_ADDR"];
		}else if (array_key_exists('HTTP_CLIENT_IP', $_SERVER)) {
			return $_SERVER["HTTP_CLIENT_IP"];
		}

		return '';
	}

}
