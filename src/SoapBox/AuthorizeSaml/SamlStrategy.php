<?php namespace SoapBox\AuthorizeSaml;

require_once(__DIR__ . '/Libraries/SimpleSAMLphp/lib/_autoload.php');

use SoapBox\Authorize\Helpers;
use SoapBox\Authorize\User;
use SoapBox\Authorize\Exceptions\MissingArgumentsException;
use SoapBox\Authorize\Exceptions\AuthenticationException;
use SoapBox\Authorize\Strategies\SingleSignOnStrategy;

class SamlStrategy extends SingleSignOnStrategy {

	/**
	 * Static array of settings configured for SimpleSAMLphp to import.
	 *
	 * Sample:
	 *	[
	 *		'sp' => [
	 *			'saml:SP',
	 *			'entityID' => 'http://dev.soapbox.co',
	 *			'idp' => 'https://openidp.feide.no',
	 *			'discoURL' => NULL,
	 *			'NameIDPolicy' => 'urn:oasis:n...t:unspecified'
	 *		]
	 *	]
	 *
	 * @var array
	 */
	public static $settings = [];

	/**
	 * Static array of metadata configured for SimpleSAMLphp to import.
	 *
	 * Sample:
	 *	[
	 *		'https://openidp.feide.no' => [
	 *			'name' => [
	 *				'en' => 'Feide OpenIdP - guest users',
	 *				'no' => 'Feide Gjestebrukere',
	 *			],
	 *			'description'          => 'Here you can ... instructions.',
	 *			'SingleSignOnService'  => 'https://openidp...SSOService.php',
	 *			'SingleLogoutService'  => 'https://openidp...ogoutService.php',
	 *			'certFingerprint'      => 'c9ed4dfb07...72047eb8a7a4cb'
	 *		]
	 *	]
	 *
	 * @var array
	 */
	public static $metadata = [];

	/**
	 * A list of urls that identify various endpoints in the SAML authentication
	 * schema. These may include acs, sso, etc.
	 *
	 * @var array
	 */
	public static $urls = [];

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

	/**
	 * The SAML instance
	 *
	 * @var SimpleSAML_Auth_Simple
	 */
	private $saml;

	/**
	 * Initializes the Saml Strategy for logging in.
	 *
	 * Sample:
	 *	[
	 *		'sp_key' => 'dope-sp',
	 *		'configuration' => [
	 *			'idp' => 'https://openidp.feide.no',
	 *			'discoURL' => null,
	 *			'NameIDPolicy' => 'urn:oasis...'
	 *		],
	 *		'metadata' => [ //Alternatively could be xml
	 *			'name' => [
	 *				'en' => 'I\'m a name'
	 *			],
	 *			'description' => 'This is a description',
	 *			'SingleSignOnService' => 'https://openidp.../idp/sign/in',
	 *			'SignleLogoutService' => 'https://openidp.../logout',
	 *			'certFingerprint' => 'fingerprint'
	 *			'certData' => 'data'
	 *		],
	 *		'redirect_url' => 'http://example.com/authorize/finish',
	 *		'error_url' => 'http://example.com/authorize/metadata',
	 *	]
	 *
	 * @param mixed[] $settings The configurations required by this SAML
	 *	strategy to authorize the user.
	 * @param callable $store A callback that will store a KVP (Key Value Pair).
	 * @param callable $load A callback that will return a value stored with the
	 *	provided key.
	 */
	public function __construct($settings = array(), $store = null, $load = null) {
		if (!isset($settings['configuration']) ||
			!isset($settings['metadata'])      ||
			!isset($settings['redirect_url'])  ||
			!isset($settings['error_url'])     ||
			!isset($settings['sp_key'])) {
			throw new MissingArgumentsException(
				'configuration, metadata (array or xml), redirect_url, and error_url parameters are required for SAML support'
			);
		}

		SamlStrategy::$settings = [
			$settings['sp_key'] => $settings['configuration']
		];

		if (
			!isset($settings['configuration']['baseurlpath']) ||
			empty($settings['configuration']['baseurlpath'])
		) {
			SamlStrategy::$settings['baseurlpath'] = '/';
		} else {
			SamlStrategy::$settings['baseurlpath'] = $settings['configuration']['baseurlpath'];
		}

		if (is_array($settings['metadata'])) {
			SamlStrategy::$metadata = [
				$settings['configuration']['idp'] => $settings['metadata']
			];
		} else {
			SamlStrategy::$metadata = SamlHelpers::parseMetadata($settings['metadata'], 'saml20-idp-remote');
		}

		SamlStrategy::$urls = [
			'acs' => $settings['urls']['acs'],
			'authorize' => $settings['urls']['authorize'],
			'sso' => $settings['urls']['sso']
		];

		$this->entityId = $settings['configuration']['entityID'];

		$this->saml = new \SimpleSAML_Auth_Simple($settings['sp_key']);

		$this->redirectUrl = $settings['redirect_url'];
		$this->errorUrl = $settings['error_url'];
	}

	/**
	 * Used to authenticate our user through one of the various methods.
	 *
	 * Sample: @see SamlStrategy::getUser()
	 *
	 * @param array parameters Contains the parameter mapping for our getUser
	 *	method
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
	 * Used to de-authenticate the user with the remote idp server.
	 *
	 * @param string $url The destination url where the user should be sent after
	 *  successful logout.
	 */
	public function logout($url) {
		$this->saml->logout($url);
	}

	/**
	 * Used to retrieve the user from the remote SAML server.
	 *
	 * Sample:
	 *	[
	 *		'parameters_map' => [
	 *			'email' => 'mail',
	 *			'id' => 'uid',
	 *			'firstname' => 'givenName',
	 *			'lastname' => 'sn'
	 *		]
	 *	]
	 *
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
			throw new AuthenticationException(null, 0, $ex);
		}

		$fields = $parameters['parameters_map'];
		$user = new User;

		if (isset($fields['email'])) {
			$user->email = Helpers::getValueOrDefault($attributes[$fields['email']], '', 0);
		} else {
			$name_id = $this->saml->getAuthData('saml:sp:NameID');
			$user->email = $name_id['Value'];
		}

		if (!isset($fields['id'])) {
			$user->id = $user->email;
		} else {
			$user->id = Helpers::getValueOrDefault($attributes[$fields['id']], '', 0);
		}

		$user->firstname = Helpers::getValueOrDefault($attributes[$fields['firstname']], '', 0);
		$user->lastname = Helpers::getValueOrDefault($attributes[$fields['lastname']], '', 0);
		$user->accessToken = 'accessToken';

		foreach ($fields as $key => $value) {
			if (isset($attributes[$value])) {
				$user->custom[$key] = Helpers::getValueOrDefault($attributes[$value], '', 0);
			}
		}

		return $user;
	}

	/**
	 * Used to handle tasks after login. This could include retrieving our users
	 * token after a successful authentication.
	 *
	 * @return array Mixed array of the tokens and other components that
	 *	validate our user.
	 */
	public function endpoint($parameters = array()) {
		$this->saml->requireAuth();
		return $this->login($parameters);
	}

	public function metadata($sourceId = 'dope-sp') {
		SamlHelpers::metadata($sourceId);
	}

	public function acs($sourceId = 'dope-sp') {
		SamlHelpers::acs($sourceId);
	}
}
