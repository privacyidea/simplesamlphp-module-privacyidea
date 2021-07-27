<?php
/**
 * This authproc filter reads the configuration for the privacyidea server.
 *
 * @author Micha Preußer <micha.preusser@netknights.it>
 * @author Jean_pierre Höhmann <jean-pierre.hoehmann@netknight.it>
 */

class sspmod_privacyidea_Auth_Process_serverconfig extends SimpleSAML_Auth_ProcessingFilter
{

    /**
     * This contains the server configuration
     * @var array
     */
    private $serverconfig;

    public function __construct(array $config, $reserved)
    {
        assert('array' === gettype($config));

        parent::__construct($config, $reserved);
        $this->serverconfig = $config;
        if (!isset($this->serverconfig['tryFirstAuthentication'])) { $this->serverconfig['tryFirstAuthentication'] = false; }
        if (!isset($this->serverconfig['doTriggerChallenge'])) { $this->serverconfig['doTriggerChallenge'] = false; }
    }

    /**
     * Load the server configuration.
     *
     * This will take the server configuration passed to the class in the constructor, and put it in the state, for the
     * other filters to use as a global configuration (which can be overridden on an individual basis).
     *
     * @param array &$state The global state of simpleSAMLphp
     */
    public function process(&$state)
    {
        assert('array' === gettype($state));

        foreach ($this->serverconfig as $key => $value) {$state['privacyidea:serverconfig'][$key] = $value;}
    }
}
