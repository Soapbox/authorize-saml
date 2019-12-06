<?php


use PHPUnit\Framework\TestCase;
use SoapBox\AuthorizeSaml\SamlHelpers;

class SamlHealpersTest extends TestCase
{
    /**
     * @test
     */
    public function it_should_do_something()
    {
        SamlHelpers::metadata('saml');
    }
}
