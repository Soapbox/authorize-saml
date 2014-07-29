<?php

// include_once(__DIR__ . '/../../../../../../../../../vendor/soapbox/authorize/src/SoapBox/Authorize/Strategy.php');
// include_once(__DIR__ . '/../../../../../../../../../vendor/soapbox/authorize/src/SoapBox/Authorize/Strategies/SingleSignOnStrategy.php');
// include_once(__DIR__ . '/../../../SamlStrategy.php');

//$metadata = SoapBox\AuthorizeSaml\SamlStrategy::$metadata;

$metadata['https://openidp.feide.no'] = array(
	'name' => array(
		'en' => 'Feide OpenIdP - guest users',
		'no' => 'Feide Gjestebrukere',
	),
	'description'          => 'Here you can login with your account on Feide RnD OpenID. If you do not already have an account on this identity provider, you can create a new one by following the create new account link and follow the instructions.',

	'SingleSignOnService'  => 'https://openidp.feide.no/simplesaml/saml2/idp/SSOService.php',
	'SingleLogoutService'  => 'https://openidp.feide.no/simplesaml/saml2/idp/SingleLogoutService.php',
	'certFingerprint'      => 'c9ed4dfb07caf13fc21e0fec1572047eb8a7a4cb'
);
