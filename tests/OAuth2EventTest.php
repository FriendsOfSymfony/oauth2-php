<?php
namespace OAuth2\Tests;

use OAuth2\Tests\Fixtures\OAuth2GrantCodeStub;
use OAuth2\Model\OAuth2Client;
use OAuth2\OAuth2;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\EventDispatcher\EventDispatcher;
use OAuth2\Tests\Fixtures\OAuth2EventSubscriberStub;
use OAuth2\OAuth2Events;

/**
 * OAuth event tests
 * 
 * @author Charles J. C Elling <tlakomistli.anakmosatlani@gmail.com>
 */
class OAuth2EventTest extends \PHPUnit_Framework_TestCase
{   
    /**
     * Test event triggering in default flow
     * 
     */
    public function testEventsTriggered()
    {
        $stub = new OAuth2GrantCodeStub();
        $stub->addClient(new OAuth2Client('blah', 'foo', ['http://www.example.com/']));
        $eventDispatcher = new EventDispatcher();
        $subscriber=new OAuth2EventSubscriberStub();
        $eventDispatcher->addSubscriber($subscriber);
        $oauth2 = new OAuth2($stub, [], $eventDispatcher);
        
        $data = new \stdClass;
        
        $oauth2->finishClientAuthorization(true, $data, new Request([
            'client_id' => 'blah',
            'redirect_uri' => 'http://www.example.com/?foo=bar',
            'response_type' => 'code',
            'state' => '42',
        ]));
        
        $code = $stub->getLastAuthCode();
        
        $inputData = [
            'grant_type' => OAuth2::GRANT_TYPE_AUTH_CODE, 
            'client_id' => 'blah', 
            'client_secret' => 'foo', 
            'redirect_uri' => 'http://www.example.com/?foo=bars', 
            'code'=> $code->getToken(),
        ];
        $request = new Request($inputData);
        
        // Grant an access token with the auth code
        $oauth2->grantAccessToken($request);
        
        $events = $subscriber->getEvents();
        $this->assertTrue($events[OAuth2Events::PRE_GRANT_AUTHORIZATION], "preGrantAuthorization not triggered");
        $this->assertTrue($events[OAuth2Events::GENERATE_AUTH_CODE], "generateAuthCode not triggered");
        $this->assertTrue($events[OAuth2Events::POST_GRANT_AUTHORIZATION], "postGrantAuthorization not triggered");
        $this->assertTrue($events[OAuth2Events::PRE_GRANT_ACCESS_TOKEN], "preGrantAccessToken not triggered");
        $this->assertTrue($events[OAuth2Events::GENERATE_ACCESS_TOKEN], "generateAccessToken not triggered");
        $this->assertTrue($events[OAuth2Events::GENERATE_REFRESH_TOKEN], "generateRefreshToken not triggered");
        $this->assertTrue($events[OAuth2Events::POST_GRANT_ACCESS_TOKEN], "postGrantAccessToken not triggered");
    }
}