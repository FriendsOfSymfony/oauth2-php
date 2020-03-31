<?php
namespace OAuth2\Tests\Fixtures;

use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use OAuth2\OAuth2Events;
use OAuth2\Event\PreGrantAuthorizationEvent;
use OAuth2\Event\GenerateTokenEvent;
use OAuth2\Event\PostGrantAuthorizationEvent;
use OAuth2\Event\PreGrantAccessTokenEvent;
use OAuth2\Event\PostGrantAccessTokenEvent;

/**
 * Simple event subscriber for testing event triggering
 * 
 * @author Charles J. C Elling <tlakomistli.anakmosatlani@gmail.com>
 */
class OAuth2EventSubscriberStub implements EventSubscriberInterface
{
    protected $events = [
        OAuth2Events::PRE_GRANT_AUTHORIZATION => false,
        OAuth2Events::GENERATE_AUTH_CODE => false,
        OAuth2Events::POST_GRANT_AUTHORIZATION => false,
        OAuth2Events::PRE_GRANT_ACCESS_TOKEN => false,
        OAuth2Events::GENERATE_ACCESS_TOKEN => false,
        OAuth2Events::GENERATE_REFRESH_TOKEN => false,
        OAuth2Events::POST_GRANT_ACCESS_TOKEN => false,
    ];
    
    public static function getSubscribedEvents()
    {
        return [
            OAuth2Events::PRE_GRANT_AUTHORIZATION => 'preGrantAuthorization',
            OAuth2Events::GENERATE_AUTH_CODE => 'generateAuthCode',
            OAuth2Events::POST_GRANT_AUTHORIZATION => 'postGrantAuthorization',
            OAuth2Events::PRE_GRANT_ACCESS_TOKEN => 'preGrantAccessToken',
            OAuth2Events::GENERATE_ACCESS_TOKEN => 'generateAccessToken',
            OAuth2Events::GENERATE_REFRESH_TOKEN => 'generateRefreshToken',
            OAuth2Events::POST_GRANT_ACCESS_TOKEN => 'postGrantAccessToken',   
        ];
    }
    
    public function preGrantAuthorization(PreGrantAuthorizationEvent $event)
    {
        $this->events[OAuth2Events::PRE_GRANT_AUTHORIZATION] = true;
    }
    
    public function generateAuthCode(GenerateTokenEvent $event)
    {
        $this->events[OAuth2Events::GENERATE_AUTH_CODE] = true;
    }
    
    public function postGrantAuthorization(PostGrantAuthorizationEvent $event)
    {
        $this->events[OAuth2Events::POST_GRANT_AUTHORIZATION] = true;
    }
    
    public function preGrantAccessToken(PreGrantAccessTokenEvent $event)
    {
        $this->events[OAuth2Events::PRE_GRANT_ACCESS_TOKEN] = true;
    }
    
    public function generateAccessToken(GenerateTokenEvent $event)
    {
        $this->events[OAuth2Events::GENERATE_ACCESS_TOKEN] = true;
    }
    
    public function generateRefreshToken(GenerateTokenEvent $event)
    {
        $this->events[OAuth2Events::GENERATE_REFRESH_TOKEN] = true;
    }
    
    public function postGrantAccessToken(PostGrantAccessTokenEvent $event)
    {
        $this->events[OAuth2Events::POST_GRANT_ACCESS_TOKEN] = true;
    }
    
    /**
     * @return array 
     */
    public function getEvents()
    {
        return $this->events;
    }   
}