<?php
namespace OAuth2\Event;

use Symfony\Component\EventDispatcher\Event;
use OAuth2\Model\IOAuth2Client;

/**
 * Event data for token generation
 * 
 * @author Charles J. C Elling <tlakomistli.anakmosatlani@gmail.com>
 *
 */
class GenerateTokenEvent extends Event
{
    /**
     * Client requesting the token
     * 
     * @var IOAuth2Client $client
     */
    protected $client;
    
    /**
     * 
     * 
     * @var mixed $data
     */
    protected $data;
    
    /**
     * Scope of the token
     * 
     * @var string|null
     */
    protected $scope = null;
    
    /**
     * Token lifetime
     * 
     * @var int|null
     */
    protected $token_lifetime = null;
    
    /**
     * Generated token
     * 
     * @var string|null
     */
    protected $token = null;
    
    /**
     * 
     * @param IOAuth2Client $client
     * @param mixed $data
     * @param string|null $scope
     * @param int|null $token_lifetime
     */
    public function __construct(IOAuth2Client $client, $data, $scope = null, $token_lifetime = null) 
    {
        $this->client = $client;
        $this->data = $data;
        $this->scope = $scope;
        $this->token_lifetime = $token_lifetime;
    }
    
    /**
     * 
     * @return IOAuth2Client
     */
    public function getClient() 
    {
        return $this->client;
    }
    
    /**
     * 
     * @return mixed
     */
    public function getData() 
    {
        return $this->data;
    }
    
    
    /**
     * 
     * @return string|null
     */
    public function getScope() 
    {
        return $this->scope;
    }
    
    /**
     * 
     * @return number|null
     */
    public function getToken_Lifetime() 
    {
        return $this->token_lifetime;
    }
    
    /**
     * 
     * @return string|null
     */
    public function getToken() 
    {
        return $this->token;
    }
    
    /**
     * 
     * @param string|null $token
     * @return self
     */
    public function setToken($token)
    {
        $this->token = $token;
        return $this;
    }
    
    
    
}

