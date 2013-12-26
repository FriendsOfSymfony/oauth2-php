<?php

use OAuth2\OAuth2;
use OAuth2\Model\OAuth2Client;
use OAuth2\Tests\Fixtures\OAuth2GrantCodeStub;
use Symfony\Component\HttpFoundation\Request;

/**
 * Enforce State test case.
 */
class OAuth2EnforceStateTest extends PHPUnit_Framework_TestCase
{
    /**
     * Test for Enforce State
     * @dataProvider dataEnforceState
     */
    public function testEnforceState(OAuth2Client $client, array $server_options, Request $request, $exception = null, $exceptionMessage = null, $exceptionDescription = null, $state_expected = false)
    {
        $stub = new OAuth2GrantCodeStub;
        $stub->addClient( $client );

        try {
            $oauth2 = new OAuth2($stub, $server_options);

            $data = new \stdClass;

            $response = $oauth2->finishClientAuthorization(true, $data, $request);

            if ($state_expected === true) {

                $this->assertRegexp('#^http://www\.example\.com/\?foo=bar&state=42&code=#', $response->headers->get('location'));
            } else {

                $this->assertRegexp('#^http://www\.example\.com/\?foo=bar&code=#', $response->headers->get('location'));
            }

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
     * Dataprovider for testEnforceState().
     */
    public function dataEnforceState()
    {
        return array(
            /* Data without state passed in the request */
            // Enforce state set to false by default
            array(
                new OAuth2Client('blah', 'foo', array('http://www.example.com/'), null, null, null, null),
                array(
                ),
                new Request(array(
                    'client_id' => 'blah',
                    'redirect_uri' => 'http://www.example.com/?foo=bar',
                    'response_type' => 'code',
                )),
                null,
                null,
                null,
                false,
            ),

            // Enforce State required by server
            array(
                new OAuth2Client('blah', 'foo', array('http://www.example.com/'), null, null, null, null),
                array(
                    OAuth2::CONFIG_ENFORCE_STATE => true
                ),
                new Request(array(
                    'client_id' => 'blah',
                    'redirect_uri' => 'http://www.example.com/?foo=bar',
                    'response_type' => 'code',
                )),
                'OAuth2\OAuth2RedirectException',
                OAuth2::ERROR_INVALID_REQUEST,
                'The state parameter is required.',
            ),

            // Enforce State required by server, but not by client
            array(
                new OAuth2Client('blah', 'foo', array('http://www.example.com/'), null, null, null, false),
                array(
                    OAuth2::CONFIG_ENFORCE_STATE => true
                ),
                new Request(array(
                    'client_id' => 'blah',
                    'redirect_uri' => 'http://www.example.com/?foo=bar',
                    'response_type' => 'code',
                )),
                null,
                null,
                null,
                false,
            ),

            // Enforce State not required by server, but by client
            array(
                new OAuth2Client('blah', 'foo', array('http://www.example.com/'), null, null, null, true),
                array(
                    OAuth2::CONFIG_ENFORCE_STATE => false
                ),
                new Request(array(
                    'client_id' => 'blah',
                    'redirect_uri' => 'http://www.example.com/?foo=bar',
                    'response_type' => 'code',
                )),
                'OAuth2\OAuth2RedirectException',
                OAuth2::ERROR_INVALID_REQUEST,
                'The state parameter is required.',
            ),

            // Enforce State required by server and client
            array(
                new OAuth2Client('blah', 'foo', array('http://www.example.com/'), null, null, null, true),
                array(
                    OAuth2::CONFIG_ENFORCE_STATE => true
                ),
                new Request(array(
                    'client_id' => 'blah',
                    'redirect_uri' => 'http://www.example.com/?foo=bar',
                    'response_type' => 'code',
                )),
                'OAuth2\OAuth2RedirectException',
                OAuth2::ERROR_INVALID_REQUEST,
                'The state parameter is required.',
            ),

            /* Dataset with state passed in the request */
            // Enforce state set to false by default
            array(
                new OAuth2Client('blah', 'foo', array('http://www.example.com/'), null, null, null, null),
                array(
                ),
                new Request(array(
                    'client_id' => 'blah',
                    'redirect_uri' => 'http://www.example.com/?foo=bar',
                    'response_type' => 'code',
                    'state' => '42'
                )),
                null,
                null,
                null,
                true,
            ),

            // Enforce State required by server
            array(
                new OAuth2Client('blah', 'foo', array('http://www.example.com/'), null, null, null, null),
                array(
                    OAuth2::CONFIG_ENFORCE_STATE => true
                ),
                new Request(array(
                    'client_id' => 'blah',
                    'redirect_uri' => 'http://www.example.com/?foo=bar',
                    'response_type' => 'code',
                    'state' => '42'
                )),
                null,
                null,
                null,
                true,
            ),

            // Enforce State required by server, but not by client
            array(
                new OAuth2Client('blah', 'foo', array('http://www.example.com/'), null, null, null, false),
                array(
                    OAuth2::CONFIG_ENFORCE_STATE => true
                ),
                new Request(array(
                    'client_id' => 'blah',
                    'redirect_uri' => 'http://www.example.com/?foo=bar',
                    'response_type' => 'code',
                    'state' => '42'
                )),
                null,
                null,
                null,
                true,
            ),

            // Enforce State not required by server, but by client
            array(
                new OAuth2Client('blah', 'foo', array('http://www.example.com/'), null, null, null, true),
                array(
                    OAuth2::CONFIG_ENFORCE_STATE => false
                ),
                new Request(array(
                    'client_id' => 'blah',
                    'redirect_uri' => 'http://www.example.com/?foo=bar',
                    'response_type' => 'code',
                    'state' => '42'
                )),
                null,
                null,
                null,
                true,
            ),

            // Enforce State required by server and client
            array(
                new OAuth2Client('blah', 'foo', array('http://www.example.com/'), null, null, null, true),
                array(
                    OAuth2::CONFIG_ENFORCE_STATE => true
                ),
                new Request(array(
                    'client_id' => 'blah',
                    'redirect_uri' => 'http://www.example.com/?foo=bar',
                    'response_type' => 'code',
                    'state' => '42'
                )),
                null,
                null,
                null,
                true,
            ),
        );
    }
}
