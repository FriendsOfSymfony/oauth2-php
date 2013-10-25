<?php

namespace OAuth2;

use Symfony\Component\HttpFoundation\Response;

/**
 * OAuth2 errors that require termination of OAuth2 due to
 * an error.
 *
 */
class OAuth2ServerException extends \Exception {
  
  protected $httpCode;
  protected $errorData = array();
  
  /**
   * @param $http_status_code
   *   HTTP status code message as predefined.
   * @param $error
   *   A single error code.
   * @param $error_description
   *   (optional) A human-readable text providing additional information,
   *   used to assist in the understanding and resolution of the error
   *   occurred.
   */
  public function __construct($http_status_code, $error, $error_description = NULL) {
    parent::__construct($error);
    
    $this->httpCode = $http_status_code;
    
    $this->errorData['error'] = $error;
    if ($error_description) {
      $this->errorData['error_description'] = $error_description;
    }
  }

  /**
   * @return string 
   */
  public function getDescription() {
    return isset($this->errorData['error_description']) ? $this->errorData['error_description'] : null;
  }
  
  /**
   * @return string 
   */
  public function getHttpCode() {
    return $this->httpCode;
  }

  /**
   * Get HTTP Error Response
   *
   * @see http://tools.ietf.org/html/draft-ietf-oauth-v2-20#section-5.1
   * @see http://tools.ietf.org/html/draft-ietf-oauth-v2-20#section-5.2
   *
   * @ingroup oauth2_error
   */
  public function getHttpResponse() {
    return new Response(
      $this->getResponseBody(),
      $this->getHttpCode(),
      $this->getResponseHeaders()
    );
  }

  /**
   * Get HTTP Error Response headers
   *
   * @see http://tools.ietf.org/html/draft-ietf-oauth-v2-20#section-5.2
   *
   * @ingroup oauth2_error
   */
  public function getResponseHeaders() {
    return array(
      'Content-Type' => 'application/json',
      'Cache-Control' => 'no-store',
      'Pragma' => 'no-cache',
    );
  }

  public function getResponseBody() {
    return json_encode($this->errorData);
  }
  
  public function sendHttpResponse() {
    $this->getHttpResponse()->send();
    exit;
  }
  
  /**
   * @see Exception::__toString()
   */
  public function __toString() {
    return $this->getResponseBody();
  }
}
