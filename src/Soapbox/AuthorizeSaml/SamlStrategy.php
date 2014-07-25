<?php namespace SoapBox\AuthorizeSaml;

use SoapBox\Authorize\Helpers;
use SoapBox\Authorize\User;
use SoapBox\Authorize\Exceptions\AuthenticationException;
use SoapBox\Authorize\Strategies\SingleSignOnStrategy;

class SamlStrategy extends SingleSignOnStrategy {

	/**
	 * The url to redirect the user to after they have granted permissions on
	 * SAML.
	 *
	 * @var string
	 */
	private $redirectUrl = '';

	/**
	 * The url to redirect the user if there was an error authenticating with
	 * SAML.
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
		if (!isset($settings['id']) ||
			!isset($settings['redirect_url']) ||
			!isset($settings['error_url'])) {
			throw new \Exception(
				'An id, redirect_url, error_url are requried to use SAML login'
			);
		}

		//Export settings for config.php, authsources.php, and saml20-idp-remote
		dd($config);

		$this->saml = new SimpleSAML_Auth_Simple($settings['id']);
		$this->saml->requireAuth();

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
			$name_id = $as->getAuthData('saml:sp:NameID');
			$user->email = $name_id['Value'];
		}

		$user->id = $this->getValueOrDefault($attributes[$paramters['id']][0], '');
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
		return $this->login();
	}

}
