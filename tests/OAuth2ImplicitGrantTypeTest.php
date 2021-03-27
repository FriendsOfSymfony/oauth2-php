<?php

use OAuth2\OAuth2;
use OAuth2\OAuth2ServerException;
use OAuth2\Model\OAuth2Client;
use OAuth2\Tests\Fixtures\OAuth2ImplicitStub;
use Symfony\Component\HttpFoundation\Request;

/**
 * OAuth2 test case.
 */
class OAuth2ImplicitGrantTypeTest extends \PHPUnit\Framework\TestCase
{
    /**
     * Tests OAuth2->grantAccessToken() with implicit
     *
     */
    public function testGrantAccessTokenWithGrantImplicit()
    {
        $stub = new OAuth2ImplicitStub();
        $stub->addClient(new OAuth2Client('blah', 'foo', array('http://www.example.com/')));
        $oauth2 = new OAuth2($stub);

        $data = new \stdClass();

        $response = $oauth2->finishClientAuthorization(true, $data, new Request(array(
                'client_id' => 'blah',
                'redirect_uri' => 'http://www.example.com/?foo=bar',
                'response_type' => 'token',
                'state' => '42',
        )));

        $this->assertRegExp('/^http:\/\/www.example.com\/\?foo=bar#state=42&access_token=[^"]+&expires_in=3600&token_type=bearer$/', $response->headers->get('Location'));
    }

    /**
     * Tests OAuth2->grantAccessToken() with implicit
     *
     */
    public function testRejectedAccessTokenWithGrantImplicit()
    {
        //$this->fixture->grantAccessToken(/* parameters */);

        $stub = new OAuth2ImplicitStub();
        $stub->addClient(new OAuth2Client('blah', 'foo', array('http://www.example.com/')));
        $oauth2 = new OAuth2($stub);

        $data = new \stdClass();

        try {
            $oauth2->finishClientAuthorization(false, $data, new Request(array(
                    'client_id' => 'blah',
                    'redirect_uri' => 'http://www.example.com/?foo=bar',
                    'state' => '42',
                    'response_type' => 'token',
            )));
            $this->fail('The expected exception OAuth2ServerException was not thrown');
        } catch (OAuth2ServerException $e) {
            $this->assertSame('access_denied', $e->getMessage());
            $this->assertSame('The user denied access to your application', $e->getDescription());
            $this->assertSame(array(
                'Location' => 'http://www.example.com/?foo=bar#error=access_denied&error_description=The+user+denied+access+to+your+application&state=42',
            ), $e->getResponseHeaders());
        }
    }
}
