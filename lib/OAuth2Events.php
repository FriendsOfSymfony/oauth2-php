<?php
namespace OAuth2;

use OAuth2\Event\PreGrantAuthorizationEvent;
use OAuth2\Event\GenerateTokenEvent;
use OAuth2\Event\PostGrantAuthorizationEvent;
use OAuth2\Event\PreGrantAccessTokenEvent;
use OAuth2\Event\PostGrantAccessTokenEvent;

/**
 * OAuth 2 Events
 * 
 * @author Charles J. C Elling <tlakomistli.anakmosatlani@gmail.com>
 */
class OAuth2Events
{
    /**
     * The PRE_GRANT_AUTHORIZATION event occurs after the user autentication and client autorization, 
     * but before the auth code generation.
     * 
     * This allows to modify the autorization parameters
     * 
     * @Event(PreGrantAuthorizationEvent::class)
     * @var string
     */
    const PRE_GRANT_AUTHORIZATION  = "oauth2.pre.grant.authorization";
    
    /**
     * The GENERATE_AUTH_CODE event occurs during the auth code generation.
     *
     * This allows to overwrite the auth code generation
     *
     * @Event(GenerateTokenEvent::class)
     * @var string
     */
    const GENERATE_AUTH_CODE       = 'oauth2.generate.auth_code';
    
    /**
     * The POST_GRANT_AUTHORIZATION event occurs after the auth code generation.
     *
     * This allows to modify the autorization response variables
     *
     * @Event(PostGrantAuthorizationEvent::class)
     * @var string
     */
    const POST_GRANT_AUTHORIZATION = "oauth2.post.grant.authorization";
    
    /**
     * The PRE_GRANT_ACCESS_TOKEN event occurs before the access token generation.
     *
     * This allows to modify the grant access token parameters
     *
     * @Event(PreGrantAccessTokenEvent::class)
     * @var string
     */
    const PRE_GRANT_ACCESS_TOKEN   = "oauth2.pre.grant.access_token";
    
    /**
     * The GENERATE_ACCESS_TOKEN event occurs during the access token generation.
     *
     * This allows to overwrite the access token generation
     *
     * @Event(GenerateTokenEvent::class)
     * @var string
     */
    const GENERATE_ACCESS_TOKEN    = 'oauth2.generate.access_token';
    
    /**
     * The GENERATE_REFRESH_TOKEN  event occurs during the refresh token generation.
     *
     * This allows to overwrite the refresh token generation
     *
     * @Event(GenerateTokenEvent::class)
     * @var string
     */
    const GENERATE_REFRESH_TOKEN   = 'oauth2.generate.refresh_token';
    
    /**
     * The POST_GRANT_ACCESS_TOKEN event occurs after the access token generation.
     *
     * This allows to modify the grant access token response variables
     *
     * @Event(PostGrantAccessTokenEvent::class)
     * @var string
     */
    const POST_GRANT_ACCESS_TOKEN  = "oauth2.post.grant.access_token"; 
}