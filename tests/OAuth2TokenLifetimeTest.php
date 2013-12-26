<?php

use OAuth2\OAuth2;
use OAuth2\Model\OAuth2Client;
use OAuth2\Tests\Fixtures\OAuth2GrantCodeStub;
use Symfony\Component\HttpFoundation\Request;

/**
 * Token lifetime test case.
 */
class OAuth2TokenLifetimeTest extends PHPUnit_Framework_TestCase
{
    /**
     * Test for Access Tokens
     * @dataProvider dataTokenLifetime
     */
    public function testTokenLifetime(OAuth2Client $client, array $server_options, $exception = null, $exceptionMessage = null, $exceptionDescription = null, $authcode_lifetime_expected = null, $access_token_lifetime_expected = null, $refresh_token_lifetime_expected = null)
    {
        $stub = new OAuth2GrantCodeStub;
        $stub->addClient( $client );

        try {
            $oauth2 = new OAuth2($stub, $server_options);

            $authcode_request = new Request(array(
                'client_id' => 'blah',
                'redirect_uri' => 'http://www.example.com/?foo=bar',
                'response_type' => 'code',
            ));
            $data = new \stdClass;

            $oauth2->finishClientAuthorization(true, $data, $authcode_request);
            $code = $stub->getLastAuthCode();

            $acces_token_request = new Request(array(
                'grant_type' => OAuth2::GRANT_TYPE_AUTH_CODE,
                'client_id' => 'blah',
                'client_secret' => 'foo',
                'redirect_uri' => 'http://www.example.com/?foo=bars',
                'code'=> $code->getToken()
            ));
            $oauth2->grantAccessToken($acces_token_request);
            $access_token = $stub->getLastAccessToken();
            $refresh_token = $stub->getLastRefreshToken();

            $this->assertSame($authcode_lifetime_expected, $code->getExpiresIn());
            $this->assertSame($access_token_lifetime_expected, $access_token->getExpiresIn());
            $this->assertSame($refresh_token_lifetime_expected, $refresh_token->getExpiresIn());

            if ($exception !== null) {
                $this->fail('The expected exception was not thrown');
            }
        } catch (\Exception $e) {
            if (!$exception || !($e instanceof $exception)) {
                throw $e;
            }
            $this->assertSame($exceptionMessage, $e->getMessage());
            $this->assertSame($exceptionDescription, $e->getDescription());
        }
    }

    /**
     * Dataprovider for testTokenLifetime().
     */
    public function dataTokenLifetime()
    {
        return array(
            // Lifetime defined by server (default values)
            array(
                new OAuth2Client('blah', 'foo', array('http://www.example.com/'), null, null, null),
                array(
                ),
                null,
                null,
                null,
                30,
                3600,
                1209600,
            ),

            // Lifetime defined by server (custom values)
            array(
                new OAuth2Client('blah', 'foo', array('http://www.example.com/'), null, null, null),
                array(
                    OAuth2::CONFIG_AUTH_LIFETIME => 60,
                    OAuth2::CONFIG_ACCESS_LIFETIME => 7200,
                    OAuth2::CONFIG_REFRESH_LIFETIME => 2419200,
                ),
                null,
                null,
                null,
                60,
                7200,
                2419200,
            ),

            // Auth Code Lifetime defined by client and other lifetimes defined by server
            array(
                new OAuth2Client('blah', 'foo', array('http://www.example.com/'), null, null, 120),
                array(
                    OAuth2::CONFIG_AUTH_LIFETIME => 30,
                    OAuth2::CONFIG_ACCESS_LIFETIME => 7200,
                    OAuth2::CONFIG_REFRESH_LIFETIME => 2419200,
                ),
                null,
                null,
                null,
                120,
                7200,
                2419200,
            ),

            // Access Token Lifetime defined by client and other lifetimes defined by server
            array(
                new OAuth2Client('blah', 'foo', array('http://www.example.com/'), 1000, null, null),
                array(
                    OAuth2::CONFIG_AUTH_LIFETIME => 60,
                    OAuth2::CONFIG_ACCESS_LIFETIME => 7200,
                    OAuth2::CONFIG_REFRESH_LIFETIME => 2419200,
                ),
                null,
                null,
                null,
                60,
                1000,
                2419200,
            ),

            // Refresh Token Lifetime defined by client and other lifetimes defined by server
            array(
                new OAuth2Client('blah', 'foo', array('http://www.example.com/'), null, 10000, null),
                array(
                    OAuth2::CONFIG_AUTH_LIFETIME => 60,
                    OAuth2::CONFIG_ACCESS_LIFETIME => 7200,
                    OAuth2::CONFIG_REFRESH_LIFETIME => 2419200,
                ),
                null,
                null,
                null,
                60,
                7200,
                10000,
            ),

            // All Lifetimes defined by client
            array(
                new OAuth2Client('blah', 'foo', array('http://www.example.com/'), 20, 30, 10),
                array(
                    OAuth2::CONFIG_AUTH_LIFETIME => 60,
                    OAuth2::CONFIG_ACCESS_LIFETIME => 7200,
                    OAuth2::CONFIG_REFRESH_LIFETIME => 2419200,
                ),
                null,
                null,
                null,
                10,
                20,
                30,
            ),
        );
    }
}
