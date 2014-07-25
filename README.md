# Authorize-Facebook
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

```

### Endpoint
```php

```
