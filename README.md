# Authorize-SAML
[Authorize](http://github.com/soapbox/authorize) strategy for SAML authentication.

## Getting Started
- Install [Authorize](http://github.com/soapbox/authorize) into your application
to use this Strategy.

## Installation
Add the following to your `composer.json`
```
"require": {
	...
	"soapbox/authorize-saml": "dev-master",
	...
}
```

### app/config/app.php
Add the following to your `app.php`, note this will be removed in future
versions since it couples us with Laravel, and it isn't required for the library
to function
```
'providers' => array(
	...
	"SoapBox\AuthorizeSaml\AuthorizeSamlServiceProvider",
	...
)
```

## Usage

### Login
```php

use SoapBox\Authroize\Authenticator;
use SoapBox\Authorize\Exceptions\InvalidStrategyException;
...
$settings = [
	'sp_key' => 'dope-sp',
	'configuration' => [
		'idp' => 'https://openidp.feide.no',
		'discoURL' => null,
		'NameIDPolicy' => 'urn:oasis...'
	],
	'metadata' => [ //Alternatively could be xml
		'name' => [
			'en' => 'I\'m a name'
		],
		'description' => 'This is a description',
		'SingleSignOnService' => 'https://openidp.../idp/sign/in',
		'SignleLogoutService' => 'https://openidp.../logout',
		'certFingerprint' => 'fingerprint'
		'certData' => 'data'
	],
	'redirect_url' => 'http://example.com/authorize/finish',
	'error_url' => 'http://example.com/authorize/metadata',
];

$strategy = new Authenticator('saml', $settings);

$parameters = 	[
	'parameters_map' => [
		'email' => 'mail',
		'id' => 'uid',
		'firstname' => 'givenName',
		'lastname' => 'sn'
	]
]

$user = $strategy->authenticate($parameters);

```

### Endpoint
```php

$settings = [
	'sp_key' => 'dope-sp',
	'configuration' => [
		'idp' => 'https://openidp.feide.no',
		'discoURL' => null,
		'NameIDPolicy' => 'urn:oasis...'
	],
	'metadata' => [ //Alternatively could be xml
		'name' => [
			'en' => 'I\'m a name'
		],
		'description' => 'This is a description',
		'SingleSignOnService' => 'https://openidp.../idp/sign/in',
		'SignleLogoutService' => 'https://openidp.../logout',
		'certFingerprint' => 'fingerprint'
		'certData' => 'data'
	],
	'redirect_url' => 'http://example.com/authorize/finish',
	'error_url' => 'http://example.com/authorize/metadata',
];

$strategy = new Authenticator($provider, $settings);

//If we're looking for the metadata endpoint
$strategy->strategy->metadata($settings['sp-key']);

//If we're lookign for the acs endpoint
$strategy->strategy->acs($settings['sp-key']);
```
