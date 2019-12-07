<?php namespace SoapBox\AuthorizeSaml;

require_once(__DIR__ . '/Libraries/SimpleSAMLphp/lib/_autoload.php');

class SamlHelpers
{
    public static function parseMetadata($xmldata)
    {
        $config = \SimpleSAML_Configuration::getInstance();

        \SimpleSAML_Utilities::validateXMLDocument($xmldata, 'saml-meta');
        $entities = \SimpleSAML_Metadata_SAMLParser::parseDescriptorsString($xmldata);

        /* Get all metadata for the entities. */
        foreach ($entities as &$entity) {
            $entity = array(
                'shib13-sp-remote' => $entity->getMetadata1xSP(),
                'shib13-idp-remote' => $entity->getMetadata1xIdP(),
                'saml20-sp-remote' => $entity->getMetadata20SP(),
                'saml20-idp-remote' => $entity->getMetadata20IdP(),
            );
        }

        /* Transpose from $entities[entityid][type] to $output[type][entityid]. */
        $output = \SimpleSAML_Utilities::transposeArray($entities);

        return $output['saml20-idp-remote'];
    }


    public static function metadata($sourceId = 'dope-sp')
    {
        $config = \SimpleSAML_Configuration::getInstance();
        $source = \SimpleSAML_Auth_Source::getById($sourceId);

        if ($source === null) {
            throw new \SimpleSAML_Error_NotFound(
                'Could not find authentication source with id ' . $sourceId
            );
        }

        if (!($source instanceof \SimpleSAML\Module\saml\Auth\Source\SP)) {
            throw new \SimpleSAML_Error_NotFound(
                'Source isn\'t a SAML SP: ' . var_export($sourceId, true)
            );
        }

        $entityId = $source->getEntityId();
        $spconfig = $source->getMetadata();
        $store = \SimpleSAML_Store::getInstance();

        $metaArray20 = array();

        $slosvcdefault = array(
            \SAML2_Const::BINDING_HTTP_REDIRECT,
            \SAML2_Const::BINDING_SOAP,
        );

        $slob = $spconfig->getArray('SingleLogoutServiceBinding', $slosvcdefault);
        $slol = \SimpleSAML_Module::getModuleURL('saml/sp/saml2-logout.php/' . $sourceId);

        foreach ($slob as $binding) {
            if ($binding == \SAML2_Const::BINDING_SOAP && !($store instanceof \SimpleSAML_Store_SQL)) {
                /* We cannot properly support SOAP logout. */
                continue;
            }
            $metaArray20['SingleLogoutService'][] = array(
                'Binding' => $binding,
                'Location' => $slol,
            );
        }

        $assertionsconsumerservicesdefault = array(
            'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
            'urn:oasis:names:tc:SAML:1.0:profiles:browser-post',
            'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact',
            'urn:oasis:names:tc:SAML:1.0:profiles:artifact-01',
        );

        if ($spconfig->getString('ProtocolBinding', '') ==
                'urn:oasis:names:tc:SAML:2.0:profiles:holder-of-key:SSO:browser') {
            $assertionsconsumerservicesdefault[] =
                'urn:oasis:names:tc:SAML:2.0:profiles:holder-of-key:SSO:browser';
        }

        $assertionsconsumerservices =
            $spconfig->getArray('acs.Bindings', $assertionsconsumerservicesdefault);

        $index = 0;
        $eps = array();
        foreach ($assertionsconsumerservices as $services) {
            $acsArray = array('index' => $index);
            switch ($services) {
                case 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST':
                    $acsArray['Binding'] = \SAML2_Const::BINDING_HTTP_POST;
                    $acsArray['Location'] = \SimpleSAML_Module::getModuleURL('saml/sp/saml2-acs.php/' . $sourceId);
                    break;
                case 'urn:oasis:names:tc:SAML:1.0:profiles:browser-post':
                    $acsArray['Binding'] = 'urn:oasis:names:tc:SAML:1.0:profiles:browser-post';
                    $acsArray['Location'] = \SimpleSAML_Module::getModuleURL('saml/sp/saml1-acs.php/' . $sourceId);
                    break;
                case 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact':
                    $acsArray['Binding'] = 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact';
                    $acsArray['Location'] = \SimpleSAML_Module::getModuleURL('saml/sp/saml2-acs.php/' . $sourceId);
                    break;
                case 'urn:oasis:names:tc:SAML:1.0:profiles:artifact-01':
                    $acsArray['Binding'] = 'urn:oasis:names:tc:SAML:1.0:profiles:artifact-01';
                    $acsArray['Location'] = \SimpleSAML_Module::getModuleURL(
                        'saml/sp/saml1-acs.php/' . $sourceId . '/artifact'
                    );
                    break;
                case 'urn:oasis:names:tc:SAML:2.0:profiles:holder-of-key:SSO:browser':
                    $acsArray['Binding'] = 'urn:oasis:names:tc:SAML:2.0:profiles:holder-of-key:SSO:browser';
                    $acsArray['Location'] = \SimpleSAML_Module::getModuleURL('saml/sp/saml2-acs.php/' . $sourceId);
                    $acsArray['hoksso:ProtocolBinding'] = \SAML2_Const::BINDING_HTTP_REDIRECT;
                    break;
            }
            $eps[] = $acsArray;
            $index++;
        }

        $metaArray20['AssertionConsumerService'] = $eps;

        $keys = array();
        $certInfo = \SimpleSAML_Utilities::loadPublicKey($spconfig, false, 'new_');
        if ($certInfo !== null && array_key_exists('certData', $certInfo)) {
            $hasNewCert = true;

            $certData = $certInfo['certData'];

            $keys[] = array(
                'type' => 'X509Certificate',
                'signing' => true,
                'encryption' => true,
                'X509Certificate' => $certInfo['certData'],
            );
        } else {
            $hasNewCert = false;
        }

        $certInfo = \SimpleSAML_Utilities::loadPublicKey($spconfig);
        if ($certInfo !== null && array_key_exists('certData', $certInfo)) {
            $certData = $certInfo['certData'];

            $keys[] = array(
                'type' => 'X509Certificate',
                'signing' => true,
                'encryption' => ($hasNewCert ? false : true),
                'X509Certificate' => $certInfo['certData'],
            );
        } else {
            $certData = null;
        }

        $format = $spconfig->getString('NameIDPolicy', null);
        if ($format !== null) {
            $metaArray20['NameIDFormat'] = $format;
        }

        $name = $spconfig->getLocalizedString('name', null);
        $attributes = $spconfig->getArray('attributes', array());

        if ($name !== null && !empty($attributes)) {
            $metaArray20['name'] = $name;
            $metaArray20['attributes'] = $attributes;
            $metaArray20['attributes.required'] = $spconfig->getArray('attributes.required', array());

            $description = $spconfig->getArray('description', null);
            if ($description !== null) {
                $metaArray20['description'] = $description;
            }

            $nameFormat = $spconfig->getString('attributes.NameFormat', null);
            if ($nameFormat !== null) {
                $metaArray20['attributes.NameFormat'] = $nameFormat;
            }
        }

        // add organization info
        $orgName = $spconfig->getLocalizedString('OrganizationName', null);
        if ($orgName !== null) {
            $metaArray20['OrganizationName'] = $orgName;

            $metaArray20['OrganizationDisplayName'] =
                $spconfig->getLocalizedString('OrganizationDisplayName', null);

            if ($metaArray20['OrganizationDisplayName'] === null) {
                $metaArray20['OrganizationDisplayName'] = $orgName;
            }

            $metaArray20['OrganizationURL'] = $spconfig->getLocalizedString('OrganizationURL', null);
            if ($metaArray20['OrganizationURL'] === null) {
                throw new \SimpleSAML_Error_Exception(
                    'If OrganizationName is set, OrganizationURL must also be set.'
                );
            }
        }

        // add technical contact
        $email = $config->getString('technicalcontact_email', 'na@example.org');
        if ($email != 'na@example.org') {
            $contact = array(
              'contactType' => 'technical',
              'emailAddress' => $email,
            );

            $name = $config->getString('technicalcontact_name', null);
            if ($name === null) {
                /* Nothing to do here... */
            } elseif (preg_match('@^(.*?)\s*,\s*(.*)$@D', $name, $matches)) {
                $contact['surName'] = $matches[1];
                $contact['givenName'] = $matches[2];
            } elseif (preg_match('@^(.*?)\s+(.*)$@D', $name, $matches)) {
                $contact['givenName'] = $matches[1];
                $contact['surName'] = $matches[2];
            } else {
                $contact['givenName'] = $name;
            }
        }

        // add additional contacts
        $contacts = $spconfig->getArray('contacts', array());

        // add certificate
        if (count($keys) === 1) {
            $metaArray20['certData'] = $keys[0]['X509Certificate'];
        } elseif (count($keys) > 1) {
            $metaArray20['keys'] = $keys;
        }

        // add UIInfo extension
        if ($spconfig->hasValue('UIInfo')) {
            $metaArray20['UIInfo'] = $spconfig->getArray('UIInfo');
        }

        // add RegistrationInfo extension
        if ($spconfig->hasValue('RegistrationInfo')) {
            $metaArray20['RegistrationInfo'] = $spconfig->getArray('RegistrationInfo');
        }

        $supported_protocols = array('urn:oasis:names:tc:SAML:1.1:protocol', \SAML2_Const::NS_SAMLP);

        $metaArray20['metadata-set'] = 'saml20-sp-remote';
        $metaArray20['entityid'] = $entityId;

        $metaBuilder = new \SimpleSAML_Metadata_SAMLBuilder($entityId);
        $metaBuilder->addMetadataSP20($metaArray20, $supported_protocols);
        $metaBuilder->addOrganizationInfo($metaArray20);

        if (!empty($contact)) {
            $metaBuilder->addContact('technical', $contact);
        }

        foreach ($contacts as $c) {
            $metaBuilder->addContact($c['contactType'], $c);
        }

        $xml = $metaBuilder->getEntityDescriptorText();

        unset($metaArray20['attributes.required']);
        unset($metaArray20['UIInfo']);
        unset($metaArray20['metadata-set']);
        unset($metaArray20['entityid']);

        /* Sign the metadata if enabled. */
        $xml = \SimpleSAML_Metadata_Signer::sign($xml, $spconfig->toArray(), 'SAML 2 SP');

        if (array_key_exists('output', $_REQUEST) && $_REQUEST['output'] == 'xhtml') {
            $t = new \SimpleSAML_XHTML_Template($config, 'metadata.php', 'admin');

            $t->data['header'] = 'saml20-sp';
            $t->data['metadata'] = htmlspecialchars($xml);
            $t->data['metadataflat'] =
                '$metadata[' . var_export($entityId, true) . '] = ' . var_export($metaArray20, true) . ';';
            $t->data['metaurl'] = $source->getMetadataURL();
            $t->show();
        } else {
            header('Content-Type: application/samlmetadata+xml');
            echo($xml);
            // For some reason laravel is turning this into a web request .... >.>
            die();
        }
    }

    public static function acs($sourceId = 'dope-sp')
    {
        $source = \SimpleSAML_Auth_Source::getById($sourceId, 'SimpleSAML\\Module\\saml\\Auth\\Source\\SP');
        $spMetadata = $source->getMetadata();

        $b = \SAML2_Binding::getCurrentBinding();
        if ($b instanceof \SAML2_HTTPArtifact) {
            $b->setSPMetadata($spMetadata);
        }

        $response = $b->receive();
        if (!($response instanceof \SAML2\Response)) {
            throw new \SimpleSAML_Error_BadRequest('Invalid message received to AssertionConsumerService endpoint.');
        }

        $idp = $response->getIssuer();
        if ($idp === null) {
            /* No Issuer in the response. Look for an unencrypted assertion with an issuer. */
            foreach ($response->getAssertions() as $a) {
                if ($a instanceof \SAML2_Assertion) {
                    /* We found an unencrypted assertion - there should be an issuer here. */
                    $idp = $a->getIssuer();
                    break;
                }
            }
            if ($idp === null) {
                /* No issuer found in the assertions. */
                throw new \Exception('Missing <saml:Issuer> in message delivered to AssertionConsumerService.');
            }
        }

        $session = \SimpleSAML_Session::getSessionFromRequest();
        $prevAuth = $session->getAuthData($sourceId, 'saml:sp:prevAuth');
        if ($prevAuth !== null && $prevAuth['id'] === $response->getId() && $prevAuth['issuer'] === $idp) {
            /* OK, it looks like this message has the same issuer
             * and ID as the SP session we already have active. We
             * therefore assume that the user has somehow triggered
             * a resend of the message.
             * In that case we may as well just redo the previous redirect
             * instead of displaying a confusing error message.
             */
            \SimpleSAML_Logger::info('Duplicate SAML 2 response detected - ignoring the response and redirecting the user to the correct page.');
            \SimpleSAML_Utilities::redirectTrustedURL($prevAuth['redirect']);
        }

        $idpMetadata = array();

        $stateId = $response->getInResponseTo();
        if (!empty($stateId)) {

            // sanitize the input
            $sid = \SimpleSAML_Utilities::parseStateID($stateId);
            if (!is_null($sid['url'])) {
                \SimpleSAML_Utilities::checkURLAllowed($sid['url']);
            }

            /* This is a response to a request we sent earlier. */
            $state = \SimpleSAML_Auth_State::loadState($stateId, 'saml:sp:sso');

            /* Check that the authentication source is correct. */
            assert('array_key_exists("saml:sp:AuthId", $state)');
            if ($state['saml:sp:AuthId'] !== $sourceId) {
                throw new \SimpleSAML_Error_Exception('The authentication source id in the URL does not match the authentication source which sent the request.');
            }

            /* Check that the issuer is the one we are expecting. */
            assert('array_key_exists("ExpectedIssuer", $state)');
            if ($state['ExpectedIssuer'] !== $idp) {
                $idpMetadata = $source->getIdPMetadata($idp);
                $idplist = $idpMetadata->getArrayize('IDPList', array());
                if (!in_array($state['ExpectedIssuer'], $idplist)) {
                    throw new \SimpleSAML_Error_Exception('The issuer of the response does not match to the identity provider we sent the request to.');
                }
            }
        } else {
            /* This is an unsolicited response. */
            $state = array(
                'saml:sp:isUnsolicited' => true,
                'saml:sp:AuthId' => $sourceId,
                'saml:sp:RelayState' => \SimpleSAML_Utilities::checkURLAllowed($response->getRelayState()),
            );
        }

        \SimpleSAML_Logger::debug('Received SAML2 Response from ' . var_export($idp, true) . '.');

        if (empty($idpMetadata)) {
            $idpMetadata = $source->getIdPmetadata($idp);
        }

        try {
            $assertions = \sspmod_saml_Message::processResponse($spMetadata, $idpMetadata, $response);
        } catch (\sspmod_saml_Error $e) {
            /* The status of the response wasn't "success". */
            $e = $e->toException();
            \SimpleSAML_Auth_State::throwException($state, $e);
        }


        $authenticatingAuthority = null;
        $nameId = null;
        $sessionIndex = null;
        $expire = null;
        $attributes = array();
        $foundAuthnStatement = false;
        foreach ($assertions as $assertion) {

            /* Check for duplicate assertion (replay attack). */
            $store = \SimpleSAML_Store::getInstance();
            if ($store !== false) {
                $aID = $assertion->getId();
                if ($store->get('saml.AssertionReceived', $aID) !== null) {
                    $e = new \SimpleSAML_Error_Exception('Received duplicate assertion.');
                    \SimpleSAML_Auth_State::throwException($state, $e);
                }

                $notOnOrAfter = $assertion->getNotOnOrAfter();
                if ($notOnOrAfter === null) {
                    $notOnOrAfter = time() + 24*60*60;
                } else {
                    $notOnOrAfter += 60; /* We allow 60 seconds clock skew, so add it here also. */
                }

                $store->set('saml.AssertionReceived', $aID, true, $notOnOrAfter);
            }


            if ($authenticatingAuthority === null) {
                $authenticatingAuthority = $assertion->getAuthenticatingAuthority();
            }
            if ($nameId === null) {
                $nameId = $assertion->getNameId();
            }
            if ($sessionIndex === null) {
                $sessionIndex = $assertion->getSessionIndex();
            }
            if ($expire === null) {
                $expire = $assertion->getSessionNotOnOrAfter();
            }

            $attributes = array_merge($attributes, $assertion->getAttributes());

            if ($assertion->getAuthnInstant() !== null) {
                /* Assertion contains AuthnStatement, since AuthnInstant is a required attribute. */
                $foundAuthnStatement = true;
            }
        }

        if (!$foundAuthnStatement) {
            $e = new \SimpleSAML_Error_Exception('No AuthnStatement found in assertion(s).');
            \SimpleSAML_Auth_State::throwException($state, $e);
        }

        if ($expire !== null) {
            $logoutExpire = $expire;
        } else {
            /* Just expire the logout associtaion 24 hours into the future. */
            $logoutExpire = time() + 24*60*60;
        }

        /* Register this session in the logout store. */
        \sspmod_saml_SP_LogoutStore::addSession($sourceId, $nameId, $sessionIndex, $logoutExpire);

        /* We need to save the NameID and SessionIndex for logout. */
        $logoutState = array(
            'saml:logout:Type' => 'saml2',
            'saml:logout:IdP' => $idp,
            'saml:logout:NameID' => $nameId,
            'saml:logout:SessionIndex' => $sessionIndex,
            );
        $state['LogoutState'] = $logoutState;
        $state['saml:AuthenticatingAuthority'] = $authenticatingAuthority;
        $state['saml:AuthenticatingAuthority'][] = $idp;
        $state['PersistentAuthData'][] = 'saml:AuthenticatingAuthority';

        $state['saml:sp:NameID'] = $nameId;
        $state['PersistentAuthData'][] = 'saml:sp:NameID';
        $state['saml:sp:SessionIndex'] = $sessionIndex;
        $state['PersistentAuthData'][] = 'saml:sp:SessionIndex';
        $state['saml:sp:AuthnContext'] = $assertion->getAuthnContext();
        $state['PersistentAuthData'][] = 'saml:sp:AuthnContext';

        if ($expire !== null) {
            $state['Expire'] = $expire;
        }

        if (isset($state['SimpleSAML_Auth_Default.ReturnURL'])) {
            /* Just note some information about the authentication, in case we receive the
             * same response again.
             */
            $state['saml:sp:prevAuth'] = array(
                'id' => $response->getId(),
                'issuer' => $idp,
                'redirect' => $state['SimpleSAML_Auth_Default.ReturnURL'],
            );
            $state['PersistentAuthData'][] = 'saml:sp:prevAuth';
        }

        $source->handleResponse($state, $idp, $attributes);
        assert('FALSE');
    }
}
