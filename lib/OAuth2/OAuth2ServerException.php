<?php

namespace OAuth2;

use Symfony\Component\HttpFoundation\Response;

/**
 * OAuth2 errors that require termination of OAuth2 due to an error.
 */
class OAuth2ServerException extends \Exception
{
    /**
     * @var string
     */
    protected $httpCode;

    /**
     * @var array
     */
    protected $errorData = array();

    /**
     * @param string $httpStatusCode   HTTP status code message as predefined.
     * @param string $error            A single error code.
     * @param string $errorDescription (optional) A human-readable text providing additional information, used to assist in the understanding and resolution of the error occurred.
     */
    public function __construct($httpStatusCode, $error, $errorDescription = null)
    {
        parent::__construct($error);

        $this->httpCode = $httpStatusCode;

        $this->errorData['error'] = $error;
        $this->errorData['error_description'] = $errorDescription;
    }

    /**
     * Get error description
     *
     * @return string
     */
    public function getDescription()
    {
        return $this->errorData['error_description'];
    }

    /**
     * Get HTTP code
     *
     * @return string
     */
    public function getHttpCode()
    {
        return $this->httpCode;
    }

    /**
     * Get HTTP Error Response
     *
     * @return Response
     *
     * @see http://tools.ietf.org/html/draft-ietf-oauth-v2-20#section-5.1
     * @see http://tools.ietf.org/html/draft-ietf-oauth-v2-20#section-5.2
     *
     * @ingroup oauth2_error
     */
    public function getHttpResponse()
    {
        return new Response(
            $this->getResponseBody(),
            $this->getHttpCode(),
            $this->getResponseHeaders()
        );
    }

    /**
     * Get HTTP Error Response headers
     *
     * @return array
     *
     * @see http://tools.ietf.org/html/draft-ietf-oauth-v2-20#section-5.2
     *
     * @ingroup oauth2_error
     */
    public function getResponseHeaders()
    {
        return array(
            'Content-Type' => 'application/json',
            'Cache-Control' => 'no-store',
            'Pragma' => 'no-cache',
        );
    }

    /**
     * Get response body as JSON string
     *
     * @return string
     */
    public function getResponseBody()
    {
        return json_encode($this->errorData);
    }

    /**
     * Outputs response
     */
    public function sendHttpResponse()
    {
        $this->getHttpResponse()->send();
        exit; // TODO: refactor out this piece of code
    }

    /**
     * @see \Exception::__toString()
     */
    public function __toString()
    {
        return $this->getResponseBody();
    }
}
