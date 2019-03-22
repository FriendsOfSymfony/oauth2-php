<?php
namespace OAuth2\Event;

use Symfony\Component\HttpFoundation\Request;
use OAuth2\Model\OAuth2Client;

/**
 * Post grant access token event data
 * 
 * @author Charles J. C Elling <tlakomistli.anakmosatlani@gmail.com>
 *
 */
class PostGrantAccessTokenEvent extends PreGrantAccessTokenEvent
{
    /**
     * Access token variables
     * 
     * @var array
     */
    protected $token;
    
    /**
     * 
     * @param array $token
     * @param Request $request
     * @param array $data
     * @param array $input
     * @param OAuth2Client $client
     */
    public function __construct(array $token, Request $request, array $data=[], $input=[], OAuth2Client $client = null)
    {
        parent::__construct($request,$data, $input, $client);
        $this->token = $token;
    }
    
    /**
     * Get the access token variables
     * 
     * @return array
     */
    public function getToken()
    {
        return $this->token;
    }

    /**
     * Set the access token variables
     * 
     * @param array $token
     * @return self
     */
    public function setToken(array $token)
    {
        $this->token = $token;
        return $this;
    }   
}