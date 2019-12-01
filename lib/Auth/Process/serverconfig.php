<?php
/**
 * This authproc filter reads the configuration for the privacyidea server.
 * @author Micha Preußer <micha.preusser@netknights.it>
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

        parent::__construct($config, $reserved);
        $cfg = SimpleSAML_Configuration::loadFromArray($config, 'privacyidea:serverconfig');
        $this->serverconfig['privacyideaserver'] = $cfg->getString('privacyideaserver', '');
        $this->serverconfig['sslverifyhost'] = $cfg->getBoolean('sslverifyhost', true);
        $this->serverconfig['sslverifypeer'] = $cfg->getBoolean('sslverifypeer', true);
        $this->serverconfig['realm'] = $cfg->getString('realm', '');
        try {
            $this->serverconfig['uidKey'] = $cfg->getArray('uidKey');
        } catch (Exception $e) {
            $this->serverconfig['uidKey'] = array($cfg->getString('uidKey', 'uid'));
        }
        $this->serverconfig['enabledPath'] = $cfg->getString('enabledPath', 'privacyIDEA');
        $this->serverconfig['enabledKey'] = $cfg->getString('enabledKey', 'enabled');
        $this->serverconfig['serviceAccount'] = $cfg->getString('serviceAccount', '');
        $this->serverconfig['servicePass'] = $cfg->getString('servicePass', '');
        $this->serverconfig['doTriggerChallenge'] = $cfg->getBoolean('doTriggerChallenge', false);
        $this->serverconfig['tryFirstAuthentication'] = $cfg->getBoolean('tryFirstAuthentication', false);
        $this->serverconfig['tryFirstAuthPass'] = $cfg->getString('tryFirstAuthPass', 'simpleSAMLphp');

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
        foreach ($this->serverconfig['uidKey'] as $uidKey) {
            if (isset($state['Attributes'][$uidKey][0])) {
                $this->serverconfig['uidKey'] = $uidKey;
                break;
            }
        }

        foreach ($this->serverconfig as $key => $value) {
            $state['privacyidea:serverconfig'][$key] = $value;
        }
    }
}
