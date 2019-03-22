<?php
namespace OAuth2\Event;

use Symfony\Component\HttpFoundation\Request;
use OAuth2\Model\OAuth2Client;
use Symfony\Component\EventDispatcher\Event;

/**
 * Pre grant acess token event data
 * 
 * @author Charles J. C Elling <tlakomistli.anakmosatlani@gmail.com>
 *
 */
class PreGrantAccessTokenEvent extends Event
{
    /**
     * HTTP request data
     * @var Request
     */
    protected $request;
    
    /**
     * OAuth 2 request filtered data
     * @var array
     */
    protected $input;
    
    /**
     * Request unfiltered data
     * @var array
     */
    protected $data;
    
    /**
     * Client requesting the access token
     * 
     * @var OAuth2Client
     */
    protected $client;
    
    
    /**
     * 
     * @param Request $request
     * @param array $data
     * @param array $input
     * @param OAuth2Client $client
     */
    public function __construct(Request $request, array $data=[], $input=[], OAuth2Client $client = null)
    {
        $this->request = $request;
        $this->input = $input;
        $this->data  = $data;
        $this->client = $client;
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
     * Get the request filtered data
     * @return array
     */
    public function getInput()
    {
        return $this->input;
    }
    
    /**
     * Get the request unfiltered data
     * 
     * @return array
     */
    public function getData()
    {
        return $this->data;
    }
    
    /**
     * Get the client requesting the access token
     * 
     * @return \OAuth2\Model\OAuth2Client
     */
    public function getClient()
    {
        return $this->client;
    }
    
    /**
     * Set request filtered data
     * 
     * @param array $input
     * @return self
     */
    public function setInput($input)
    {
        $this->input = $input;
        return $this;
    }
    
    /**
     * Set request unfiltered data
     * 
     * @param array $data
     * @return self
     */
    public function setData($data)
    {
        $this->data = $data;
        return $this;
    }
    
    /**
     * Set the client requesting the access token
     * 
     * @param \OAuth2\Model\OAuth2Client $client
     * @return self
     */
    public function setClient($client)
    {
        $this->client = $client;
        return $this;
    }
}