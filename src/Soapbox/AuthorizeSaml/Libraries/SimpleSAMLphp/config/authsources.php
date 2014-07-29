<?php

require_once(__DIR__ . '/../../../../../../../authorize/src/SoapBox/Authorize/Strategy.php');
require_once(__DIR__ . '/../../../../../../../authorize/src/SoapBox/Authorize/Strategies/SingleSignOnStrategy.php');
require_once(__DIR__ . '/../../../SamlStrategy.php');

$config = SoapBox\AuthorizeSaml\SamlStrategy::$settings;
