<?php

namespace OAuth2;

/**
 * Send an error header with the given realm and an error, if provided.
 * Suitable for the bearer token type.
 *
 * @see http://tools.ietf.org/html/draft-ietf-oauth-v2-bearer-04#section-2.4
 *
 * @ingroup oauth2_error
 */
class OAuth2AuthenticateException extends OAuth2ServerException
{
    protected $header;

    /**
     *
     * @param $http_status_code
     *   HTTP status code message as predefined.
     * @param $error
     *   The "error" attribute is used to provide the client with the reason
     *   why the access request was declined.
     * @param $error_description
     *   (optional) The "error_description" attribute provides a human-readable text
     *   containing additional information, used to assist in the understanding
     *   and resolution of the error occurred.
     * @param $scope
     *   A space-delimited list of scope values indicating the required scope
     *   of the access token for accessing the requested resource.
     */
    public function __construct($httpCode, $tokenType, $realm, $error, $error_description = NULL, $scope = NULL)
    {
        parent::__construct($httpCode, $error, $error_description);

        if ($scope) {
            $this->errorData['scope'] = $scope;
        }

        // Build header
        $header = sprintf('%s realm=%s', ucwords($tokenType), $this->quotedString($realm));
        foreach ($this->errorData as $key => $value) {
            $header .= sprintf(', %s=%s', $key, $this->quotedString($value));
        }
        $this->header = array('WWW-Authenticate' => $header);
    }

    public function getResponseHeaders()
    {
        return $this->header + parent::getResponseHeaders();
    }

    private function quotedString($str)
    {
        // https://tools.ietf.org/html/draft-ietf-httpbis-p1-messaging-17#section-3.2.3
        $str = preg_replace('~
            [^
                \x21-\x7E
                \x80-\xFF
                \ \t
            ]
            ~x', '', $str);
        $str = addcslashes($str, '"\\');

        return '"' . $str . '"';
    }
}
