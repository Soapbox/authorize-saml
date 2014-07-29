<?php

// include_once(__DIR__ . '/../../../../../../../../../vendor/soapbox/authorize/src/SoapBox/Authorize/Strategy.php');
// include_once(__DIR__ . '/../../../../../../../../../vendor/soapbox/authorize/src/SoapBox/Authorize/Strategies/SingleSignOnStrategy.php');
// include_once(__DIR__ . '/../../../SamlStrategy.php');

//$config = SoapBox\AuthorizeSaml\SamlStrategy::$settings;
$config = array(

	// This is a authentication source which handles admin authentication.
	'admin' => array(
		// The default is to use core:AdminPassword, but it can be replaced with
		// any authentication source.

		'core:AdminPassword',
	),

	// An authentication source which can authenticate against both SAML 2.0
	// and Shibboleth 1.3 IdPs.
	'dope-sp' => array(
		'saml:SP',
		//'privatekey' => 'saml.pem',
		//'certificate' => 'saml.crt',

		// The entity ID of this SP.
		// Can be NULL/unset, in which case an entity ID is generated based on the metadata URL.
		'entityID' => 'http://62448ee9.ngrok.com/simplesaml/module.php/saml/sp/metadata.php/dope-sp',

		// The entity ID of the IdP this should SP should contact.
		// Can be NULL/unset, in which case the user will be shown a list of available IdPs.
		'idp' => 'https://openidp.feide.no',

		// The URL to the discovery service.
		// Can be NULL/unset, in which case a builtin discovery service will be used.
		'discoURL' => NULL,
	)
);
