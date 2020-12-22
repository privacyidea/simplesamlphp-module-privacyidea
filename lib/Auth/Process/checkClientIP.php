<?php
/**
 * This Auth Proc Filter allows to check the IP of the client and to control the
 * two-factor authentication of the following privacyIDEA Auth Proc Filter depending on the client IP.
 * For example, it can be used to configure that a user does not need to provide a
 * second factor when logging in from the local network.
 * @author Micha Preußer <micha.preusser@netknights.it>
 */

class sspmod_privacyidea_Auth_Process_checkClientIP extends SimpleSAML_Auth_ProcessingFilter
{

    /**
     * enter excluded ip addresses
     * @var array|mixed
     */
    private $excludeClientIPs = array();

    public function __construct(array $config, $reserved)
    {
        assert('array' === gettype($config));

        parent::__construct($config, $reserved);
        $this->excludeClientIPs = $config['excludeClientIPs'];
    }

    /**
     * Check the clients IP against the whitelist.
     *
     * @param array &$state The global state of simpleSAMLphp
     */
    public function process(&$state)
    {
        assert('array' === gettype($state));

        $state['privacyIDEA']['enabled'][0] = $this->matchIP(sspmod_privacyidea_Auth_utils::getClientIP());
    }

    private function matchIP($clientIP) {
        assert('string' === gettype($clientIP));
        $clientIP = ip2long($clientIP);

        $match = false;
        foreach ($this->excludeClientIPs as $ipAddress) {
            if (strpos($ipAddress, '-')) {
                $range = explode('-', $ipAddress);
                $startIP = ip2long($range[0]);
                $endIP = ip2long($range[1]);
                $match = $clientIP >= $startIP && $clientIP <= $endIP;
            } else {
                $match = $clientIP === ip2long($ipAddress);
            }
            if ($match) {break;}
        }
        return $match;
    }
}
