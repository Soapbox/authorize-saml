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

	public function metadata($sourceId = 'dope-sp') {

		$config = \SimpleSAML_Configuration::getInstance();
		$source = \SimpleSAML_Auth_Source::getById($sourceId);

		if ($source === null) {
			throw new \SimpleSAML_Error_NotFound(
				'Could not find authentication source with id ' . $sourceId
			);
		}

		if (!($source instanceof \sspmod_saml_Auth_Source_SP)) {
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

			$contact = array('emailAddress' => $email);

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
		}
	}

}
