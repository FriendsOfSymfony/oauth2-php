<?php
namespace OAuth2\Event;

use Symfony\Component\EventDispatcher\GenericEvent;
use Symfony\Component\HttpFoundation\Request;

/**
 * 
 * 
 * @author Charles J. C Elling <tlakomistli.anakmosatlani@gmail.com>
 */
class PreGrantAuthorizationEvent extends GenericEvent
{
    /**
     * HTTP request data
     * 
     * @var Request
     */
    protected $request;
    
    /**
     * OAuth 2 authorization data
     * 
     * @var array
     */
    protected $params;
    
    /**
     * Is the client authorized by the user
     * 
     * @var boolean
     */
    protected $isAuthorized;
    
    /**
     * 
     * @param Request $request
     * @param array $params
     * @param boolean $isAuthorized
     */
    public function __construct(Request $request, array $params, $isAuthorized)
    {
        parent::__construct();
        $this->request = $request;
        $this->params = $params;
        $this->isAuthorized = $isAuthorized;
    }
    /**
     * Get the HTTP request data
     * 
     * @return \Symfony\Component\HttpFoundation\Request
     */
    public function getRequest()
    {
        return $this->request;
    }

    /**
     * Get the authorization data
     * 
     * @return array
     */
    public function getParams()
    {
        return $this->params;
    }

    /**
     * Is the client authorized by the user
     * 
     * @return boolean
     */
    public function isIsAuthorized()
    {
        return $this->isAuthorized;
    }

    /**
     * Set the authorization data
     * 
     * @param array $params
     * @return self
     */
    public function setParams($params)
    {
        $this->params = $params;
        return $this;
    }
}