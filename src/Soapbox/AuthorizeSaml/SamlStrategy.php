<?php namespace SoapBox\AuthorizeSaml;

require_once(__DIR__ . '/Libraries/SimpleSAMLphp/lib/_autoload.php');

use SoapBox\Authorize\Helpers;
use SoapBox\Authorize\User;
use SoapBox\Authorize\Exceptions\AuthenticationException;
use SoapBox\Authorize\Strategies\SingleSignOnStrategy;

class SamlStrategy extends SingleSignOnStrategy {

	/**
	 * Static array of settings configured for SimpleSAMLphp to import.
	 *
	 * @var array [
	 *		'sp' => [
	 *			'saml:SP',
	 *			'entityID' => 'http://dev.soapbox.co',
	 *			'idp' => 'https://openidp.feide.no',
	 *			'discoURL' => NULL,
	 *			'NameIDPolicy' => 'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified'
	 *		]
	 *	]
	 */
	public static $settings = [];

	/**
	 * Static array of metadata configured for SimpleSAMLphp to import.
	 *
	 * @var array [
	 *		'https://openidp.feide.no' => [
	 *			'name' => [
	 *				'en' => 'Feide OpenIdP - guest users',
	 *				'no' => 'Feide Gjestebrukere',
	 *			],
	 *			'description'          => 'Here you can login with your account on Feide RnD OpenID. If you do not already have an account on this identity provider, you can create a new one by following the create new account link and follow the instructions.',
	 *			'SingleSignOnService'  => 'https://openidp.feide.no/simplesaml/saml2/idp/SSOService.php',
	 *			'SingleLogoutService'  => 'https://openidp.feide.no/simplesaml/saml2/idp/SingleLogoutService.php',
	 *			'certFingerprint'      => 'c9ed4dfb07caf13fc21e0fec1572047eb8a7a4cb'
	 *		]
	 *	]
	 */
	public static $metadata = [];

	/**
	 * The url to redirect to after the sign in process was successful
	 *
	 * @var string
	 */
	private $redirectUrl = '';

	/**
	 * The url to reidrect to if the sign in process fails
	 *
	 * @var string
	 */
	private $errorUrl = '';

	private $urls = array();

	/**
	 * The SAML instance
	 *
	 * @var SimpleSAML_Auth_Simple
	 */
	private $saml;

	/**
	 * Returns the default if the value is not set.
	 *
	 * @param $value mixed The value you wish to validate.
	 * @param $default mixed The value you wish to get if value is not set
	 *
	 * @return mixed
	 */
	private function getValueOrDefault($value, $default) {
		if (isset($value)) {
			return $value;
		}
		return $default;
	}

	/**
	 * Initializes the Saml Strategy for logging in.
	 *
	 * @param array $settings ...
	 */
	public function __construct($settings = array()) {
		if (!isset($settings['configuration']) ||
			!isset($settings['metadata']) ||
			!isset($settings['redirect_url']) ||
			!isset($settings['error_url']) ||
			!isset($settings['sp_key'])) {
			throw new \Exception(
				'configuration, metadata, redirect_url, and error_url parameters are required for SAML support'
			);
		}

		SamlStrategy::$settings = [
			$settings['sp_key'] => $settings['configuration']
		];

		SamlStrategy::$metadata = [
			$settings['configuration']['idp'] => $settings['metadata']
		];

		$this->entityId = $settings['configuration']['entityID'];

		$this->saml = new \SimpleSAML_Auth_Simple($settings['sp_key']);

		$this->redirectUrl = $settings['redirect_url'];
		$this->errorUrl = $settings['error_url'];
	}

	/**
	 * Used to authenticate our user through one of the various methods.
	 *
	 * @param array parameters ...
	 *
	 * @throws AuthenticationException If the provided parameters do not
	 *	successfully authenticate.
	 *
	 * @return User A mixed array representing the authenticated user.
	 */
	public function login($parameters = array()) {
		$this->saml->requireAuth();
		if (!$this->saml->isAuthenticated()) {
			$this->saml->login([
				'ErrorURL' => $this->errorUrl,
				'ReturnTo' => $this->redirectUrl
			]);
		}

		return $this->getUser($parameters);
	}

	/**
	 * Used to retrieve the user from the remote SAML server.
	 *
	 * @param array parameters The parameters required to authenticate against
	 *	this strategy.
	 *
	 * @throws AuthenticationException If the provided parameters do not
	 *	successfully authenticate.
	 *
	 * @return User A mixed array representing the authenticated user.
	 */
	public function getUser($parameters = array()) {
		$this->saml->requireAuth();
		if (!$this->saml->isAuthenticated()) {
			return $this->login($parameters);
		}

		try {
			$attributes = $this->saml->getAttributes();
		} catch (\Exception $ex) {
			throw new AuthenticationException();
		}

		$user = new User;

		if (isset($parameters['email'])) {
			$user->email = $this->getValueOrDefault($attributes[$parameters['email']][0], '');
		} else {
			$name_id = $attributes->getAuthData('saml:sp:NameID');
			$user->email = $name_id['Value'];
		}

		$user->id = $this->getValueOrDefault($attributes[$parameters['id']][0], '');
		$user->firstname = $this->getValueOrDefault($attributes[$parameters['firstname']][0], '');
		$user->lastname = $this->getValueOrDefault($attributes[$parameters['lastname']][0], '');

		return $user;
	}

	/**
	 * Used to handle tasks after login. This could include retrieving our users
	 * token after a successful authentication.
	 *
	 * @return array Mixed array of the tokens and other components that
	 *	validate our user.
	 */
	public function endpoint() {
		$this->saml->requireAuth();
		return $this->login();
	}

}
