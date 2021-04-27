<?php

use OAuth2\TokenGenerator\RandomTokenGenerator;

class RandomTokenGeneratorTest extends PHPUnit_Framework_TestCase
{
    public function testGenerateAccessToken()
    {
        $tokenGenerator = new RandomTokenGenerator();
        $client = $this->getMockBuilder('OAuth2\Model\IOAuth2Client')->getMock();

        $this->assertNotEmpty($tokenGenerator->genAccessToken($client, null));
    }

    public function testGenerateRefreshToken()
    {
        $tokenGenerator = new RandomTokenGenerator();
        $client = $this->getMockBuilder('OAuth2\Model\IOAuth2Client')->getMock();

        $this->assertNotEmpty($tokenGenerator->genRefreshToken($client, null));
    }

    public function testGenerateAuthCode()
    {
        $tokenGenerator = new RandomTokenGenerator();
        $client = $this->getMockBuilder('OAuth2\Model\IOAuth2Client')->getMock();

        $this->assertNotEmpty($tokenGenerator->genAuthCode($client, null));
    }
}
