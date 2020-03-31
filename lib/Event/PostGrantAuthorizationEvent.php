<?php
namespace OAuth2\Event;

use Symfony\Component\HttpFoundation\Request;

/**
 * Post grant authorization event data
 * 
 * @author Charles J. C Elling <tlakomistli.anakmosatlani@gmail.com>
 *
 */
class PostGrantAuthorizationEvent extends PreGrantAuthorizationEvent
{
    
    /**
     * Result parameters
     * 
     * @var array
     */
    protected $result;
    
    /**
     * 
     * @param array $result
     * @param Request $request
     * @param array $params
     * @param boolean $isAuthorized
     */
    public function __construct(array $result, Request $request, array $params, $isAuthorized)
    {
        parent::__construct($request, $params, $isAuthorized);
        $this->result = $result;
    }
    
    /**
     * Get the result parameters
     * 
     * @return mixed
     */
    public function getResult()
    {
        return $this->result;
    }

    /**
     * Set the result parameters
     * 
     * @param array $result
     * @return self
     */
    public function setResult(array $result)
    {
        $this->result = $result;
        return $this;
    }   
}