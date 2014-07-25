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
	 * Initializes the Saml Strategy for logging in.
	 *
	 * @param array $settings ...
	 */
	public function __construct($settings = array()) {
		//Do something ...
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
		//Do something ...
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
		//Do something ...
	}

	/**
	 * Used to handle tasks after login. This could include retrieving our users
	 * token after a successful authentication.
	 *
	 * @return array Mixed array of the tokens and other components that
	 *	validate our user.
	 */
	public function endpoint() {
		//Do something ...
	}

}
