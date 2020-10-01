<?php
/**
 * This Auth Proc Filter allows the selective activation or deactivation of privacyIDEA for
 * a list of SAML service providers.
 * It checks the entityid in the SAML request against a list of SAML entityids. Depending on
 * the configuration it sets the variable $state['privacyIDEA']['enabled'][0] to true or false
 * to activate privacyIDEA using the enabledPath (privacyIDEA) and enabledKey (enabled)
 * parameters.
 * @author Henning Hollermann <henning.hollermann@netknights.it>
 */

class sspmod_privacyIDEA_Auth_Process_checkEntityID extends SimpleSAML_Auth_ProcessingFilter {

    private $entityids = array();
    private $attributeconditions = array();
    private $onmatch = false;
    private $setPath = '';
    private $setKey = '';

    public function __construct(array $config, $reserved)
    {
        SimpleSAML_Logger::info("Checking requesting entity ID for privacyIDEA");
        parent::__construct($config, $reserved);
        $cfg = SimpleSAML_Configuration::loadFromArray($config, 'privacyidea:checkEntityID');
        $this->entityids = $cfg->getArray('entityids', null);
        $this->attributeconditions = $cfg->getArray('attributeconditions', null);
        $this->onmatch = $cfg->getBoolean('onmatch', null);
        $this->setPath = $cfg->getString('setPath', null);
        $this->setKey = $cfg->getString('setKey', null);

    }

    public function process( &$state ) {
        // the default return value is the opposite of the onmatch value.
        $ret = !$this->onmatch;
        $entityid = $state["Destination"]["entityid"];
                if (in_array($entityid, $this->entityids)) {
                    // if the requesting entityid matches the given list, check if there
                    // are further conditions in the attributes (e.g. memberOf values)
                    // and set the return value if there is a match
                    if (isset($this->attributeconditions[$entityid])) {
                        foreach($this->attributeconditions[$entityid] as $attr => $values) {
                            $intersect = array_intersect($this->attributeconditions[$entityid][$attr],
                                $state["Attributes"][$attr]);
                            if(!empty($intersect)) {
                                $ret = $this->onmatch;
                            } else {
                                SimpleSAML_Logger::debug("Requesting entityID in list, 
                                but required attributes not contained.");
                            }
                        }
                    } else {
                        // if there are no further conditions, a simple match suffices
                        $ret = $this->onmatch;
                    }
                } else {
                    SimpleSAML_Logger::debug("Requesting entityID ". $entityid ." not in list.");
                }
                $state[$this->setPath][$this->setKey][0] = $ret;
        }


}
