<?php

namespace OAuth2;

use OAuth2\Model\IOAuth2AccessToken;
use OAuth2\Model\IOAuth2AuthCode;
use OAuth2\Model\IOAuth2Client;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * @mainpage
 *
 * OAuth 2.0 server in PHP, originally written for
 * <a href="http://www.opendining.net/"> Open Dining</a>. Supports
 * <a href="http://tools.ietf.org/html/draft-ietf-oauth-v2-20">IETF draft v20</a>.
 *
 * Source repo has sample servers implementations for
 * <a href="http://php.net/manual/en/book.pdo.php"> PHP Data Objects</a> and
 * <a href="http://www.mongodb.org/">MongoDB</a>. Easily adaptable to other
 * storage engines.
 *
 * PHP Data Objects supports a variety of databases, including MySQL,
 * Microsoft SQL Server, SQLite, and Oracle, so you can try out the sample
 * to see how it all works.
 *
 * We're expanding the wiki to include more helpful documentation, but for
 * now, your best bet is to view the oauth.php source - it has lots of
 * comments.
 *
 * @author Tim Ridgely <tim.ridgely@gmail.com>
 * @author Aaron Parecki <aaron@parecki.com>
 * @author Edison Wong <hswong3i@pantarei-design.com>
 * @author David Rochwerger <catch.dave@gmail.com>
 *
 * @see    http://code.google.com/p/oauth2-php/
 * @see    https://github.com/quizlet/oauth2-php
 */

/**
 * OAuth2.0 draft v20 server-side implementation.
 *
 * @todo   Add support for Message Authentication Code (MAC) token type.
 *
 * @author Originally written by Tim Ridgely <tim.ridgely@gmail.com>.
 * @author Updated to draft v10 by Aaron Parecki <aaron@parecki.com>.
 * @author Debug, coding style clean up and documented by Edison Wong <hswong3i@pantarei-design.com>.
 * @author Refactored (including separating from raw POST/GET) and updated to draft v20 by David Rochwerger <catch.dave@gmail.com>.
 */
class OAuth2
{
    /**
     * Array of persistent variables stored.
     */
    protected $conf = array();

    /**
     * Storage engine for authentication server
     *
     * @var IOAuth2Storage
     */
    protected $storage;

    /**
     * Keep track of the old refresh token. So we can unset
     * the old refresh tokens when a new one is issued.
     *
     * @var string
     */
    protected $oldRefreshToken = null;

    /**
     * Keep track of the used auth code. So we can mark it
     * as used after successful authorization
     *
     * @var IOAuth2AuthCode
     */
    protected $usedAuthCode = null;

    /**
     * Default access token lifetime.
     *
     * The lifetime of access token in seconds.
     *
     * @var int
     *
     * @see OAuth2::setDefaultOptions()
     */
    const DEFAULT_ACCESS_TOKEN_LIFETIME = 3600;

    /**
     * Default refresh token lifetime.
     *
     * The lifetime of refresh token in seconds.
     *
     * @var int
     *
     * @see OAuth2::setDefaultOptions()
     */
    const DEFAULT_REFRESH_TOKEN_LIFETIME = 1209600;

    /**
     * Default auth code lifetime.
     *
     * The lifetime of auth code in seconds.
     *
     * @var int
     *
     * @see OAuth2::setDefaultOptions()
     */
    const DEFAULT_AUTH_CODE_LIFETIME = 30;

    /**
     * Default WWW realm
     *
     * @var string
     *
     * @see OAuth2::setDefaultOptions()
     */
    const DEFAULT_WWW_REALM = 'Service';

    /**
     * Configurable options.
     */
    const CONFIG_ACCESS_LIFETIME = 'access_token_lifetime'; // The lifetime of access token in seconds.
    const CONFIG_REFRESH_LIFETIME = 'refresh_token_lifetime'; // The lifetime of refresh token in seconds.
    const CONFIG_AUTH_LIFETIME = 'auth_code_lifetime'; // The lifetime of auth code in seconds.
    const CONFIG_SUPPORTED_SCOPES = 'supported_scopes'; // Array of scopes you want to support
    const CONFIG_TOKEN_TYPE = 'token_type'; // Token type to respond with. Currently only "Bearer" supported.
    const CONFIG_WWW_REALM = 'realm';
    const CONFIG_ENFORCE_INPUT_REDIRECT = 'enforce_redirect'; // Set to true to enforce redirect_uri on input for both authorize and token steps.
    const CONFIG_ENFORCE_STATE = 'enforce_state'; // Set to true to enforce state to be passed in authorization (see http://tools.ietf.org/html/draft-ietf-oauth-v2-21#section-10.12)
    const CONFIG_RESPONSE_EXTRA_HEADERS = 'response_extra_headers'; // Add extra headers to the response

    /**
     * Regex to filter out the client identifier (described in Section 2 of IETF draft).
     *
     * IETF draft does not prescribe a format for these, so we just check that
     * it's not empty.
     *
     * @var string
     */
    const CLIENT_ID_REGEXP = '/.+/';

    /**
     * @defgroup oauth2_section_5 Accessing a Protected Resource
     * @{
     *
     * Clients access protected resources by presenting an access token to
     * the resource server. Access tokens act as bearer tokens, where the
     * token string acts as a shared symmetric secret. This requires
     * treating the access token with the same care as other secrets (e.g.
     * end-user passwords). Access tokens SHOULD NOT be sent in the clear
     * over an insecure channel.
     *
     * @see      http://tools.ietf.org/html/draft-ietf-oauth-v2-20#section-7
     */

    /**
     * Used to define the name of the OAuth access token parameter
     * (POST & GET). This is for the "bearer" token type.
     * Other token types may use different methods and names.
     *
     * IETF Draft section 2 specifies that it should be called "access_token"
     *
     * @see http://tools.ietf.org/html/draft-ietf-oauth-v2-bearer-06#section-2.2
     * @see http://tools.ietf.org/html/draft-ietf-oauth-v2-bearer-06#section-2.3
     *
     * @var string
     */
    const TOKEN_PARAM_NAME = 'access_token';

    /**
     * When using the bearer token type, there is a specifc Authorization header
     * required: "Bearer"
     *
     * @see http://tools.ietf.org/html/draft-ietf-oauth-v2-bearer-04#section-2.1
     *
     * @var string
     */
    const TOKEN_BEARER_HEADER_NAME = 'Bearer';

    /**
     * @}
     */

    /**
     * @defgroup oauth2_section_4 Obtaining Authorization
     * @{
     *
     * When the client interacts with an end-user, the end-user MUST first
     * grant the client authorization to access its protected resources.
     * Once obtained, the end-user authorization grant is expressed as an
     * authorization code which the client uses to obtain an access token.
     * To obtain an end-user authorization, the client sends the end-user to
     * the end-user authorization endpoint.
     *
     * @see      http://tools.ietf.org/html/draft-ietf-oauth-v2-20#section-4
     */

    /**
     * List of possible authentication response types.
     * The "authorization_code" mechanism exclusively supports 'code'
     * and the "implicit" mechanism exclusively supports 'token'.
     *
     * @see http://tools.ietf.org/html/draft-ietf-oauth-v2-20#section-4.1.1
     * @see http://tools.ietf.org/html/draft-ietf-oauth-v2-20#section-4.2.1
     *
     * @var string
     */
    const RESPONSE_TYPE_AUTH_CODE = 'code';
    const RESPONSE_TYPE_ACCESS_TOKEN = 'token';

    /**
     * @}
     */

    /**
     * @defgroup oauth2_section_5 Obtaining an Access Token
     * @{
     *
     * The client obtains an access token by authenticating with the
     * authorization server and presenting its authorization grant (in the form of
     * an authorization code, resource owner credentials, an assertion, or a
     * refresh token).
     *
     * @see      http://tools.ietf.org/html/draft-ietf-oauth-v2-20#section-4
     */

    /**
     * Grant types support by draft 20
     */
    const GRANT_TYPE_AUTH_CODE = 'authorization_code';
    const GRANT_TYPE_IMPLICIT = 'token';
    const GRANT_TYPE_USER_CREDENTIALS = 'password';
    const GRANT_TYPE_CLIENT_CREDENTIALS = 'client_credentials';
    const GRANT_TYPE_REFRESH_TOKEN = 'refresh_token';
    const GRANT_TYPE_EXTENSIONS = 'extensions';

    /**
     * Regex to filter out the grant type.
     * NB: For extensibility, the grant type can be a URI
     *
     * @see http://tools.ietf.org/html/draft-ietf-oauth-v2-20#section-4.5
     */
    const GRANT_TYPE_REGEXP = '#^(authorization_code|token|password|client_credentials|refresh_token|https?://.+|urn:.+)$#';

    /**
     * @}
     */

    /**
     * Possible token types as defined by draft 20.
     *
     * TODO: Add support for mac (and maybe other types?)
     *
     * @see http://tools.ietf.org/html/draft-ietf-oauth-v2-20#section-7.1
     */
    const TOKEN_TYPE_BEARER = 'bearer';
    const TOKEN_TYPE_MAC = 'mac'; // Currently unsupported

    /**
     * @defgroup self::HTTP_status HTTP status code
     * @{
     */

    /**
     * HTTP status codes for successful and error states as specified by draft 20.
     *
     * @see http://tools.ietf.org/html/draft-ietf-oauth-v2-20#section-4.1.2
     * @see http://tools.ietf.org/html/draft-ietf-oauth-v2-20#section-5.2
     */
    const HTTP_FOUND = '302 Found';
    const HTTP_BAD_REQUEST = '400 Bad Request';
    const HTTP_UNAUTHORIZED = '401 Unauthorized';
    const HTTP_FORBIDDEN = '403 Forbidden';
    const HTTP_UNAVAILABLE = '503 Service Unavailable';

    /**
     * @}
     */

    /**
     * @defgroup oauth2_error Error handling
     * @{
     *
     * @todo     Extend for i18n.
     * @todo     Consider moving all error related functionality into a separate class.
     */

    /**
     * The request is missing a required parameter, includes an unsupported
     * parameter or parameter value, or is otherwise malformed.
     *
     * @see http://tools.ietf.org/html/draft-ietf-oauth-v2-20#section-4.1.2.1
     * @see http://tools.ietf.org/html/draft-ietf-oauth-v2-20#section-4.2.2.1
     * @see http://tools.ietf.org/html/draft-ietf-oauth-v2-20#section-5.2
     */
    const ERROR_INVALID_REQUEST = 'invalid_request';

    /**
     * The client identifier provided is invalid.
     *
     * @see http://tools.ietf.org/html/draft-ietf-oauth-v2-20#section-5.2
     */
    const ERROR_INVALID_CLIENT = 'invalid_client';

    /**
     * The client is not authorized to use the requested response type.
     *
     * @see http://tools.ietf.org/html/draft-ietf-oauth-v2-20#section-4.1.2.1
     * @see http://tools.ietf.org/html/draft-ietf-oauth-v2-20#section-4.2.2.1
     * @see http://tools.ietf.org/html/draft-ietf-oauth-v2-20#section-5.2
     */
    const ERROR_UNAUTHORIZED_CLIENT = 'unauthorized_client';

    /**
     * The redirection URI provided does not match a pre-registered value.
     *
     * @see http://tools.ietf.org/html/draft-ietf-oauth-v2-20#section-3.1.2.4
     */
    const ERROR_REDIRECT_URI_MISMATCH = 'redirect_uri_mismatch';

    /**
     * The end-user or authorization server denied the request.
     * This could be returned, for example, if the resource owner decides to reject
     * access to the client at a later point.
     *
     * @see http://tools.ietf.org/html/draft-ietf-oauth-v2-20#section-4.1.2.1
     * @see http://tools.ietf.org/html/draft-ietf-oauth-v2-20#section-4.2.2.1
     */
    const ERROR_USER_DENIED = 'access_denied';

    /**
     * The requested response type is not supported by the authorization server.
     *
     * @see http://tools.ietf.org/html/draft-ietf-oauth-v2-20#section-4.1.2.1
     * @see http://tools.ietf.org/html/draft-ietf-oauth-v2-20#section-4.2.2.1
     */
    const ERROR_UNSUPPORTED_RESPONSE_TYPE = 'unsupported_response_type';

    /**
     * The requested scope is invalid, unknown, or malformed.
     *
     * @see http://tools.ietf.org/html/draft-ietf-oauth-v2-20#section-4.1.2.1
     * @see http://tools.ietf.org/html/draft-ietf-oauth-v2-20#section-4.2.2.1
     */
    const ERROR_INVALID_SCOPE = 'invalid_scope';

    /**
     * The provided authorization grant is invalid, expired,
     * revoked, does not match the redirection URI used in the
     * authorization request, or was issued to another client.
     *
     * @see http://tools.ietf.org/html/draft-ietf-oauth-v2-20#section-5.2
     */
    const ERROR_INVALID_GRANT = 'invalid_grant';

    /**
     * The authorization grant is not supported by the authorization server.
     *
     * @see http://tools.ietf.org/html/draft-ietf-oauth-v2-20#section-5.2
     */
    const ERROR_UNSUPPORTED_GRANT_TYPE = 'unsupported_grant_type';

    /**
     * The request requires higher privileges than provided by the access token.
     * The resource server SHOULD respond with the HTTP 403 (Forbidden) status
     * code and MAY include the "scope" attribute with the scope necessary to
     * access the protected resource.
     *
     * @see http://tools.ietf.org/html/draft-ietf-oauth-v2-20#section-4.1.2.1
     * @see http://tools.ietf.org/html/draft-ietf-oauth-v2-20#section-4.2.2.1
     * @see http://tools.ietf.org/html/draft-ietf-oauth-v2-20#section-5.2
     */
    const ERROR_INSUFFICIENT_SCOPE = 'invalid_scope';

    /**
     * Access tokens and error message can be transported from the authorization endpoint to the redirect URI
     * using the query or the fragment component
     *
     * @var string
     */
    const TRANSPORT_QUERY    = 'query';
    const TRANSPORT_FRAGMENT = 'fragment';

    /**
     * @}
     */

    /**
     * Creates an OAuth2.0 server-side instance.
     *
     * @param IOAuth2Storage $storage
     * @param array          $config An associative array as below of config options. See CONFIG_* constants.
     */
    public function __construct(IOAuth2Storage $storage, $config = array())
    {
        $this->storage = $storage;

        // Configuration options
        $this->setDefaultOptions();
        foreach ($config as $name => $value) {
            $this->setVariable($name, $value);
        }
    }

    /**
     * Default configuration options are specified here.
     */
    protected function setDefaultOptions()
    {
        $this->conf = array(
            self::CONFIG_ACCESS_LIFETIME => self::DEFAULT_ACCESS_TOKEN_LIFETIME,
            self::CONFIG_REFRESH_LIFETIME => self::DEFAULT_REFRESH_TOKEN_LIFETIME,
            self::CONFIG_AUTH_LIFETIME => self::DEFAULT_AUTH_CODE_LIFETIME,
            self::CONFIG_WWW_REALM => self::DEFAULT_WWW_REALM,
            self::CONFIG_TOKEN_TYPE => self::TOKEN_TYPE_BEARER,
            // We have to enforce this only when no URI or more than one URI is
            // registered; however it's safer to enforce this by default since
            // a client may break by just registering more than one URI.
            self::CONFIG_ENFORCE_INPUT_REDIRECT => true,
            self::CONFIG_ENFORCE_STATE => false,
            self::CONFIG_SUPPORTED_SCOPES => null,
            // This is expected to be passed in on construction. Scopes can be an aribitrary string.
            self::CONFIG_RESPONSE_EXTRA_HEADERS => array(),
        );
    }

    /**
     * Returns a persistent variable.
     *
     * @param string $name    The name of the variable to return.
     * @param mixed  $default The default value to use if this variable has never been set.
     *
     * @return mixed   The value of the variable.
     */
    public function getVariable($name, $default = null)
    {
        $name = strtolower($name);

        return isset($this->conf[$name]) ? $this->conf[$name] : $default;
    }

    /**
     * Sets a persistent variable.
     *
     * @param  string $name  The name of the variable to set.
     * @param  mixed  $value The value to set.
     *
     * @return OAuth2 The application (for chained calls of this method)
     */
    public function setVariable($name, $value)
    {
        $name = strtolower($name);

        $this->conf[$name] = $value;

        return $this;
    }

    // Resource protecting (Section 5).

    /**
     * Check that a valid access token has been provided.
     * The token is returned (as an associative array) if valid.
     *
     * The scope parameter defines any required scope that the token must have.
     * If a scope param is provided and the token does not have the required
     * scope, we bounce the request.
     *
     * Some implementations may choose to return a subset of the protected
     * resource (i.e. "public" data) if the user has not provided an access
     * token or if the access token is invalid or expired.
     *
     * The IETF spec says that we should send a 401 Unauthorized header and
     * bail immediately so that's what the defaults are set to. You can catch
     * the exception thrown and behave differently if you like (log errors, allow
     * public access for missing tokens, etc)
     *
     * @param string $tokenParam
     * @param string $scope A space-separated string of required scope(s), if you want to check for scope.
     *
     * @throws OAuth2AuthenticateException
     * @return IOAuth2AccessToken Token
     *
     * @see     http://tools.ietf.org/html/draft-ietf-oauth-v2-20#section-7
     *
     * @ingroup oauth2_section_7
     */
    public function verifyAccessToken($tokenParam, $scope = null)
    {
        $tokenType = $this->getVariable(self::CONFIG_TOKEN_TYPE);
        $realm = $this->getVariable(self::CONFIG_WWW_REALM);

        if (!$tokenParam) { // Access token was not provided
            throw new OAuth2AuthenticateException(self::HTTP_BAD_REQUEST, $tokenType, $realm, self::ERROR_INVALID_REQUEST, 'The request is missing a required parameter, includes an unsupported parameter or parameter value, repeats the same parameter, uses more than one method for including an access token, or is otherwise malformed.', $scope);
        }

        // Get the stored token data (from the implementing subclass)
        $token = $this->storage->getAccessToken($tokenParam);
        if (!$token) {
            throw new OAuth2AuthenticateException(self::HTTP_UNAUTHORIZED, $tokenType, $realm, self::ERROR_INVALID_GRANT, 'The access token provided is invalid.', $scope);
        }

        // Check token expiration (expires is a mandatory paramter)
        if ($token->hasExpired()) {
            throw new OAuth2AuthenticateException(self::HTTP_UNAUTHORIZED, $tokenType, $realm, self::ERROR_INVALID_GRANT, 'The access token provided has expired.', $scope);
        }

        // Check scope, if provided
        // If token doesn't have a scope, it's null/empty, or it's insufficient, then throw an error
        if ($scope && (!$token->getScope() || !$this->checkScope($scope, $token->getScope()))) {
            throw new OAuth2AuthenticateException(self::HTTP_FORBIDDEN, $tokenType, $realm, self::ERROR_INSUFFICIENT_SCOPE, 'The request requires higher privileges than provided by the access token.', $scope);
        }

        return $token;
    }

    /**
     * This is a convenience function that can be used to get the token, which can then
     * be passed to verifyAccessToken(). The constraints specified by the draft are
     * attempted to be adheared to in this method.
     *
     * As per the Bearer spec (draft 8, section 2) - there are three ways for a client
     * to specify the bearer token, in order of preference: Authorization Header,
     * POST and GET.
     *
     * NB: Resource servers MUST accept tokens via the Authorization scheme
     * (http://tools.ietf.org/html/draft-ietf-oauth-v2-bearer-08#section-2).
     *
     * @todo Should we enforce TLS/SSL in this function?
     *
     * @see  http://tools.ietf.org/html/draft-ietf-oauth-v2-bearer-08#section-2.1
     * @see  http://tools.ietf.org/html/draft-ietf-oauth-v2-bearer-08#section-2.2
     * @see  http://tools.ietf.org/html/draft-ietf-oauth-v2-bearer-08#section-2.3
     *
     * @param Request $request
     * @param bool    $removeFromRequest
     *
     * @return string|null
     * @throws OAuth2AuthenticateException
     */
    public function getBearerToken(Request $request = null, $removeFromRequest = false)
    {
        if ($request === null) {
            $request = Request::createFromGlobals();
        }

        $tokens = array();

        $token = $this->getBearerTokenFromHeaders($request, $removeFromRequest);
        if ($token !== null) {
            $tokens[] = $token;
        }

        $token = $this->getBearerTokenFromFormEncodedBody($request, $removeFromRequest);
        if ($token !== null) {
            $tokens[] = $token;
        }

        $token = $this->getBearerTokenFromQuery($request, $removeFromRequest);
        if ($token !== null) {
            $tokens[] = $token;
        }

        if (count($tokens) > 1) {
            $realm = $this->getVariable(self::CONFIG_WWW_REALM);
            $tokenType = $this->getVariable(self::CONFIG_TOKEN_TYPE);
            throw new OAuth2AuthenticateException(self::HTTP_BAD_REQUEST, $tokenType, $realm, self::ERROR_INVALID_REQUEST, 'Only one method may be used to authenticate at a time (Auth header, GET or POST).');
        }

        if (count($tokens) < 1) {
            // Don't throw exception here as we may want to allow non-authenticated
            // requests.
            return null;
        }

        return reset($tokens);
    }

    /**
     * Get the access token from the header
     *
     * Old Android version bug (at least with version 2.2)
     *
     * @see http://code.google.com/p/android/issues/detail?id=6684
     *
     * @param Request $request
     * @param bool    $removeFromRequest
     *
     * @return string|null
     */
    protected function getBearerTokenFromHeaders(Request $request, $removeFromRequest)
    {
        $header = null;
        if (!$request->headers->has('AUTHORIZATION')) {
            // The Authorization header may not be passed to PHP by Apache;
            // Trying to obtain it through apache_request_headers()
            if (function_exists('apache_request_headers')) {
                $headers = apache_request_headers();

                if (is_array($headers)) {

                    // Server-side fix for bug in old Android versions (a nice side-effect of this fix means we don't care about capitalization for Authorization)
                    $headers = array_combine(array_map('ucwords', array_keys($headers)), array_values($headers));

                    if (isset($headers['Authorization'])) {
                        $header = $headers['Authorization'];
                    }
                }
            }
        } else {
            $header = $request->headers->get('AUTHORIZATION');
        }

        if (!$header) {
            return null;
        }


        if (!preg_match('/' . preg_quote(self::TOKEN_BEARER_HEADER_NAME, '/') . '\s(\S+)/', $header, $matches)) {
            return null;
        }

        $token = $matches[1];

        if ($removeFromRequest) {
            $request->headers->remove('AUTHORIZATION');
        }

        return $token;
    }

    /**
     * Get the token from url encoded entity-body.
     *
     * @link http://tools.ietf.org/html/rfc6750#section-2.2
     *
     * @param Request $request
     * @param bool    $removeFromRequest
     *
     * @return string|null
     */
    protected function getBearerTokenFromFormEncodedBody(Request $request, $removeFromRequest)
    {
        if (false === $request->server->has('CONTENT_TYPE')) {
            return null;
        }

        $contentType = $request->server->get('CONTENT_TYPE');

        if (!preg_match('/^application\/x-www-form-urlencoded([\s|;].*)?$/', $contentType)) {
            return null;
        }

        if ('GET' === $request->getMethod()) {
            return null;
        }

        // S2 request only decodes form encoded parameters for PUT, DELETE, PATCH. Because we are not so picky, we can't use Request::$request parameter bag...
        $body = $request->getContent();
        parse_str($body, $parameters);

        if (false === is_array($parameters)) {
            return null;
        }

        if (false === array_key_exists(self::TOKEN_PARAM_NAME, $parameters)) {
            return null;
        }

        $token = $parameters[self::TOKEN_PARAM_NAME];

        if ($removeFromRequest) {
            // S2 request content is immutable, so we can't do nothing more than crippled implementation below...
            if (true === $request->request->has(self::TOKEN_PARAM_NAME)) {
                $request->request->remove(self::TOKEN_PARAM_NAME);
            }
        }

        return $token;
    }

    /**
     * Get the token from the query string
     *
     * @param Request $request
     * @param bool    $removeFromRequest
     *
     * @return string|null
     */
    protected function getBearerTokenFromQuery(Request $request, $removeFromRequest)
    {
        if (!$token = $request->query->get(self::TOKEN_PARAM_NAME)) {
            return null;
        }

        if ($removeFromRequest) {
            $request->query->remove(self::TOKEN_PARAM_NAME);
        }

        return $token;
    }

    /**
     * Check if everything in required scope is contained in available scope.
     *
     * @param string $requiredScope  Required scope to be check with.
     * @param string $availableScope Supported scopes.
     *
     * @return bool Return true if everything in required scope is contained in available scope or false if it isn't.
     *
     * @see     http://tools.ietf.org/html/draft-ietf-oauth-v2-20#section-7
     *
     * @ingroup oauth2_section_7
     */
    protected function checkScope($requiredScope, $availableScope)
    {
        // The required scope should match or be a subset of the available scope
        if (!is_array($requiredScope)) {
            $requiredScope = explode(' ', trim($requiredScope));
        }

        if (!is_array($availableScope)) {
            $availableScope = explode(' ', trim($availableScope));
        }

        return (count(array_diff($requiredScope, $availableScope)) == 0);
    }

    // Access token granting (Section 4).

    /**
     * Grant or deny a requested access token.
     *
     * This would be called from the "/token" endpoint as defined in the spec.
     * Obviously, you can call your endpoint whatever you want.
     * Draft specifies that the authorization parameters should be retrieved from POST, but you can override to whatever method you like.
     *
     * @param  Request $request (optional) The request
     *
     * @return Response
     * @throws OAuth2ServerException
     *
     * @see      http://tools.ietf.org/html/draft-ietf-oauth-v2-20#section-4
     * @see      http://tools.ietf.org/html/draft-ietf-oauth-v2-21#section-10.6
     * @see      http://tools.ietf.org/html/draft-ietf-oauth-v2-21#section-4.1.3
     *
     * @ingroup  oauth2_section_4
     */
    public function grantAccessToken(Request $request = null)
    {
        $filters = array(
            "grant_type" => array(
                "filter" => FILTER_VALIDATE_REGEXP,
                "options" => array("regexp" => self::GRANT_TYPE_REGEXP),
                "flags" => FILTER_REQUIRE_SCALAR
            ),
            "scope" => array("flags" => FILTER_REQUIRE_SCALAR),
            "code" => array("flags" => FILTER_REQUIRE_SCALAR),
            "redirect_uri" => array("filter" => FILTER_SANITIZE_URL),
            "username" => array("flags" => FILTER_REQUIRE_SCALAR),
            "password" => array("flags" => FILTER_REQUIRE_SCALAR),
            "refresh_token" => array("flags" => FILTER_REQUIRE_SCALAR),
        );

        if ($request === null) {
            $request = Request::createFromGlobals();
        }

        // Input data by default can be either POST or GET
        if ($request->getMethod() === 'POST') {
            $inputData = $request->request->all();
        } else {
            $inputData = $request->query->all();
        }

        // Basic authorization header
        $authHeaders = $this->getAuthorizationHeader($request);

        // Filter input data
        $input = filter_var_array($inputData, $filters);

        // Grant Type must be specified.
        if (!$input["grant_type"]) {
            throw new OAuth2ServerException(self::HTTP_BAD_REQUEST, self::ERROR_INVALID_REQUEST, 'Invalid grant_type parameter or parameter missing');
        }

        // Authorize the client
        $clientCredentials = $this->getClientCredentials($inputData, $authHeaders);

        $client = $this->storage->getClient($clientCredentials[0]);

        if (!$client) {
            throw new OAuth2ServerException(self::HTTP_BAD_REQUEST, self::ERROR_INVALID_CLIENT, 'The client credentials are invalid');
        }

        if ($this->storage->checkClientCredentials($client, $clientCredentials[1]) === false) {
            throw new OAuth2ServerException(self::HTTP_BAD_REQUEST, self::ERROR_INVALID_CLIENT, 'The client credentials are invalid');
        }

        if (!$this->storage->checkRestrictedGrantType($client, $input["grant_type"])) {
            throw new OAuth2ServerException(self::HTTP_BAD_REQUEST, self::ERROR_UNAUTHORIZED_CLIENT, 'The grant type is unauthorized for this client_id');
        }

        // Do the granting
        switch ($input["grant_type"]) {
            case self::GRANT_TYPE_AUTH_CODE:
                // returns array('data' => data, 'scope' => scope)
                $stored = $this->grantAccessTokenAuthCode($client, $input);
                break;
            case self::GRANT_TYPE_USER_CREDENTIALS:
                // returns: true || array('scope' => scope)
                $stored = $this->grantAccessTokenUserCredentials($client, $input);
                break;
            case self::GRANT_TYPE_CLIENT_CREDENTIALS:
                // returns: true || array('scope' => scope)
                $stored = $this->grantAccessTokenClientCredentials($client, $input, $clientCredentials);
                break;
            case self::GRANT_TYPE_REFRESH_TOKEN:
                // returns array('data' => data, 'scope' => scope)
                $stored = $this->grantAccessTokenRefreshToken($client, $input);
                break;
            default:
                if (substr($input["grant_type"], 0, 4) !== 'urn:'
                    && !filter_var($input["grant_type"], FILTER_VALIDATE_URL)
                ) {
                    throw new OAuth2ServerException(
                        self::HTTP_BAD_REQUEST,
                        self::ERROR_INVALID_REQUEST,
                        'Invalid grant_type parameter or parameter missing'
                    );
                }

                // returns: true || array('scope' => scope)
                $stored = $this->grantAccessTokenExtension($client, $inputData, $authHeaders);
        }

        if (!is_array($stored)) {
            $stored = array();
        }

        // if no scope provided to check against $input['scope'] then application defaults are set
        // if no data is provided than null is set
        $stored += array('scope' => $this->getVariable(self::CONFIG_SUPPORTED_SCOPES, null), 'data' => null,
                         'access_token_lifetime' => $this->getVariable(self::CONFIG_ACCESS_LIFETIME),
                         'issue_refresh_token' => true, 'refresh_token_lifetime' => $this->getVariable(self::CONFIG_REFRESH_LIFETIME));

        $scope = $stored['scope'];
        if ($input["scope"]) {
            // Check scope, if provided
            if (!isset($stored["scope"]) || !$this->checkScope($input["scope"], $stored["scope"])) {
                throw new OAuth2ServerException(self::HTTP_BAD_REQUEST, self::ERROR_INVALID_SCOPE, 'An unsupported scope was requested.');
            }
            $scope = $input["scope"];
        }

        $token = $this->createAccessToken($client, $stored['data'], $scope, $stored['access_token_lifetime'], $stored['issue_refresh_token'], $stored['refresh_token_lifetime']);
        return new Response(json_encode($token), 200, $this->getJsonHeaders());
    }

    /**
     * @param IOAuth2Client $client
     * @param array         $input
     *
     * @return array
     * @throws OAuth2ServerException
     */
    protected function grantAccessTokenAuthCode(IOAuth2Client $client, array $input)
    {
        if (!($this->storage instanceof IOAuth2GrantCode)) {
            throw new OAuth2ServerException(self::HTTP_BAD_REQUEST, self::ERROR_UNSUPPORTED_GRANT_TYPE);
        }

        if (!$input["code"]) {
            throw new OAuth2ServerException(self::HTTP_BAD_REQUEST, self::ERROR_INVALID_REQUEST, 'Missing parameter. "code" is required');
        }

        if ($this->getVariable(self::CONFIG_ENFORCE_INPUT_REDIRECT) && !$input["redirect_uri"]) {
            throw new OAuth2ServerException(self::HTTP_BAD_REQUEST, self::ERROR_INVALID_REQUEST, "The redirect URI parameter is required.");
        }

        $authCode = $this->storage->getAuthCode($input["code"]);

        // Check the code exists
        if ($authCode === null || $client->getPublicId() !== $authCode->getClientId()) {
            throw new OAuth2ServerException(self::HTTP_BAD_REQUEST, self::ERROR_INVALID_GRANT, "Code doesn't exist or is invalid for the client");
        }

        // Validate the redirect URI. If a redirect URI has been provided on input, it must be validated
        if ($input["redirect_uri"] && !$this->validateRedirectUri(
                $input["redirect_uri"],
                $authCode->getRedirectUri()
            )
        ) {
            throw new OAuth2ServerException(self::HTTP_BAD_REQUEST, self::ERROR_REDIRECT_URI_MISMATCH, "The redirect URI is missing or do not match");
        }

        if ($authCode->hasExpired()) {
            throw new OAuth2ServerException(self::HTTP_BAD_REQUEST, self::ERROR_INVALID_GRANT, "The authorization code has expired");
        }

        $this->usedAuthCode = $authCode;

        return array(
            'scope' => $authCode->getScope(),
            'data' => $authCode->getData(),
        );
    }

    /**
     * @param IOAuth2Client $client
     * @param array         $input
     *
     * @return array|bool
     * @throws OAuth2ServerException
     */
    protected function grantAccessTokenUserCredentials(IOAuth2Client $client, array $input)
    {
        if (!($this->storage instanceof IOAuth2GrantUser)) {
            throw new OAuth2ServerException(self::HTTP_BAD_REQUEST, self::ERROR_UNSUPPORTED_GRANT_TYPE);
        }

        if (!$input["username"] || !$input["password"]) {
            throw new OAuth2ServerException(self::HTTP_BAD_REQUEST, self::ERROR_INVALID_REQUEST, 'Missing parameters. "username" and "password" required');
        }

        $stored = $this->storage->checkUserCredentials($client, $input["username"], $input["password"]);

        if ($stored === false) {
            throw new OAuth2ServerException(self::HTTP_BAD_REQUEST, self::ERROR_INVALID_GRANT, "Invalid username and password combination");
        }

        return $stored;
    }

    /**
     * @param IOAuth2Client $client
     * @param array         $input
     * @param array         $clientCredentials
     *
     * @return array|bool
     * @throws OAuth2ServerException
     */
    protected function grantAccessTokenClientCredentials(IOAuth2Client $client, array $input, array $clientCredentials)
    {
        if (!($this->storage instanceof IOAuth2GrantClient)) {
            throw new OAuth2ServerException(self::HTTP_BAD_REQUEST, self::ERROR_UNSUPPORTED_GRANT_TYPE);
        }

        if (empty($clientCredentials[1])) {
            throw new OAuth2ServerException(self::HTTP_BAD_REQUEST, self::ERROR_INVALID_CLIENT, 'The client_secret is mandatory for the "client_credentials" grant type');
        }

        $stored = $this->storage->checkClientCredentialsGrant($client, $clientCredentials[1]);

        if ($stored === false) {
            throw new OAuth2ServerException(self::HTTP_BAD_REQUEST, self::ERROR_INVALID_GRANT);
        }

        if (!is_array($stored)) {
            $stored = array();
        }
        $stored += array('issue_refresh_token' => false);
        return $stored;
    }

    /**
     * @param IOAuth2Client $client
     * @param array         $input
     *
     * @return array
     * @throws OAuth2ServerException
     */
    protected function grantAccessTokenRefreshToken(IOAuth2Client $client, array $input)
    {
        if (!($this->storage instanceof IOAuth2RefreshTokens)) {
            throw new OAuth2ServerException(self::HTTP_BAD_REQUEST, self::ERROR_UNSUPPORTED_GRANT_TYPE);
        }

        if (!$input["refresh_token"]) {
            throw new OAuth2ServerException(self::HTTP_BAD_REQUEST, self::ERROR_INVALID_REQUEST, 'No "refresh_token" parameter found');
        }

        $token = $this->storage->getRefreshToken($input["refresh_token"]);

        if ($token === null || $client->getPublicId() !== $token->getClientId()) {
            throw new OAuth2ServerException(self::HTTP_BAD_REQUEST, self::ERROR_INVALID_GRANT, 'Invalid refresh token');
        }

        if ($token->hasExpired()) {
            throw new OAuth2ServerException(self::HTTP_BAD_REQUEST, self::ERROR_INVALID_GRANT, 'Refresh token has expired');
        }

        // store the refresh token locally so we can delete it when a new refresh token is generated
        $this->oldRefreshToken = $token->getToken();

        return array(
            'scope' => $token->getScope(),
            'data' => $token->getData(),
        );
    }

    protected function grantAccessTokenExtension(IOAuth2Client $client, array $inputData, array $authHeaders)
    {
        if (!($this->storage instanceof IOAuth2GrantExtension)) {
            throw new OAuth2ServerException(self::HTTP_BAD_REQUEST, self::ERROR_UNSUPPORTED_GRANT_TYPE);
        }

        $uri = $inputData["grant_type"];
        if (substr($uri, 0, 4) !== 'urn:') {
            $uri = filter_var($uri, FILTER_VALIDATE_URL);
        }

        $stored = $this->storage->checkGrantExtension($client, $uri, $inputData, $authHeaders);

        if ($stored === false) {
            throw new OAuth2ServerException(self::HTTP_BAD_REQUEST, self::ERROR_INVALID_GRANT);
        }

        return $stored;
    }

    /**
     * Internal function used to get the client credentials from HTTP basic
     * auth or POST data.
     *
     * According to the spec (draft 20), the client_id can be provided in
     * the Basic Authorization header (recommended) or via GET/POST.
     *
     * @param array $inputData
     * @param array $authHeaders
     *
     * @throws OAuth2ServerException
     * @return array A list containing the client identifier and password, for example
     * @code
     * return array(
     *   CLIENT_ID,
     *   CLIENT_SECRET
     * );
     * @endcode
     *
     * @see     http://tools.ietf.org/html/draft-ietf-oauth-v2-20#section-2.4.1
     *
     * @ingroup oauth2_section_2
     */
    protected function getClientCredentials(array $inputData, array $authHeaders)
    {
        // Basic Authentication is used
        if (!empty($authHeaders['PHP_AUTH_USER'])) {
            return array($authHeaders['PHP_AUTH_USER'], $authHeaders['PHP_AUTH_PW']);
        } elseif (empty($inputData['client_id'])) { // No credentials were specified
            throw new OAuth2ServerException(self::HTTP_BAD_REQUEST, self::ERROR_INVALID_CLIENT, 'Client id was not found in the headers or body');
        } else {
            // This method is not recommended, but is supported by specification
            $client_id = $inputData['client_id'];
            $client_secret = isset($inputData['client_secret']) ? $inputData['client_secret'] : null;

            return array($client_id, $client_secret);
        }
    }

    // End-user/client Authorization (Section 2 of IETF Draft).

    /**
     * Pull the authorization request data out of the HTTP $request.
     *   - The redirect_uri is OPTIONAL as per draft 20. But your implementation can enforce it by setting
     *     CONFIG_ENFORCE_INPUT_REDIRECT to true.
     *   - The state is OPTIONAL but recommended to enforce CSRF. Draft 21 states, however, that CSRF protection is
     *     MANDATORY. You can enforce this by setting the CONFIG_ENFORCE_STATE to true.
     *
     * @param Request $request
     *
     * @return array
     *
     * @throws OAuth2ServerException
     * @throws OAuth2RedirectException
     *
     * @see     http://tools.ietf.org/html/draft-ietf-oauth-v2-20#section-4.1.1
     * @see     http://tools.ietf.org/html/draft-ietf-oauth-v2-21#section-10.12
     *
     * @ingroup oauth2_section_3
     */
    protected function getAuthorizeParams(Request $request = null)
    {
        $filters = array(
            "client_id" => array(
                "filter" => FILTER_VALIDATE_REGEXP,
                "options" => array("regexp" => self::CLIENT_ID_REGEXP),
                "flags" => FILTER_REQUIRE_SCALAR
            ),
            "response_type" => array("flags" => FILTER_REQUIRE_SCALAR),
            "redirect_uri" => array("filter" => FILTER_SANITIZE_URL),
            "state" => array("flags" => FILTER_REQUIRE_SCALAR),
            "scope" => array("flags" => FILTER_REQUIRE_SCALAR),
        );

        if ($request === null) {
            $request = Request::createFromGlobals();
        }

        /**
         * $inputData The draft specifies that the parameters should be retrieved from GET, but you can override to whatever method you like.
         *
         * @var array
         */
        $inputData = $request->query->all();
        $input = filter_var_array($inputData, $filters);

        // Make sure a valid client id was supplied (we can not redirect because we were unable to verify the URI)
        if (!$input["client_id"]) {
            throw new OAuth2ServerException(self::HTTP_BAD_REQUEST, self::ERROR_INVALID_REQUEST, "No client id supplied"); // We don't have a good URI to use
        }

        // Get client details
        $client = $this->storage->getClient($input["client_id"]);
        if (!$client) {
            throw new OAuth2ServerException(self::HTTP_BAD_REQUEST, self::ERROR_INVALID_CLIENT, 'Unknown client');
        }

        $input["redirect_uri"] = $this->getRedirectUri($input["redirect_uri"], $client);

        // type and client_id are required
        if (!$input["response_type"]) {
            throw new OAuth2RedirectException($input["redirect_uri"], self::ERROR_INVALID_REQUEST, 'Invalid response type.', $input["state"]);
        }

        // Check requested auth response type against interfaces of storage engine
        if ($input['response_type'] == self::RESPONSE_TYPE_AUTH_CODE) {
            if (!$this->storage instanceof IOAuth2GrantCode) {
                throw new OAuth2RedirectException($input["redirect_uri"], self::ERROR_UNSUPPORTED_RESPONSE_TYPE, null, $input["state"]);
            }
        } elseif ($input['response_type'] == self::RESPONSE_TYPE_ACCESS_TOKEN) {
            if (!$this->storage instanceof IOAuth2GrantImplicit) {
                throw new OAuth2RedirectException($input["redirect_uri"], self::ERROR_UNSUPPORTED_RESPONSE_TYPE, null, $input["state"], self::TRANSPORT_FRAGMENT);
            }
        } else {
            throw new OAuth2RedirectException($input["redirect_uri"], self::ERROR_UNSUPPORTED_RESPONSE_TYPE, null, $input["state"]);
        }

        // Validate that the requested scope is supported
        if ($input["scope"] && !$this->checkScope($input["scope"], $this->getVariable(self::CONFIG_SUPPORTED_SCOPES))) {
            throw new OAuth2RedirectException($input["redirect_uri"], self::ERROR_INVALID_SCOPE, 'An unsupported scope was requested.', $input["state"]);
        }

        // Validate state parameter exists (if configured to enforce this)
        if ($this->getVariable(self::CONFIG_ENFORCE_STATE) && !$input["state"]) {
            throw new OAuth2RedirectException($input["redirect_uri"], self::ERROR_INVALID_REQUEST, "The state parameter is required.");
        }

        // Return retrieved client details together with input
        return array(
            'client' => $client,
        ) + $input;
    }

    protected function getRedirectUri($redirectUri, IOAuth2Client $client)
    {
        // Make sure a valid redirect_uri was supplied. If specified, it must match the stored URI.
        // @see http://tools.ietf.org/html/draft-ietf-oauth-v2-20#section-3.1.2
        // @see http://tools.ietf.org/html/draft-ietf-oauth-v2-20#section-4.1.2.1
        // @see http://tools.ietf.org/html/draft-ietf-oauth-v2-20#section-4.2.2.1


        // If multiple redirection URIs have been registered, or if no redirection
        // URI has been registered, the client MUST include a redirection URI with
        // the authorization request using the "redirect_uri" request parameter.

        if (empty($redirectUri)) {
            if (!$client->getRedirectUris()) {
                throw new OAuth2ServerException(self::HTTP_BAD_REQUEST, self::ERROR_REDIRECT_URI_MISMATCH, 'No redirect URL was supplied or registered.');
            }
            if (count($client->getRedirectUris()) > 1) {
                throw new OAuth2ServerException(self::HTTP_BAD_REQUEST, self::ERROR_REDIRECT_URI_MISMATCH, 'No redirect URL was supplied and more than one is registered.');
            }
            if ($this->getVariable(self::CONFIG_ENFORCE_INPUT_REDIRECT)) {
                throw new OAuth2ServerException(self::HTTP_BAD_REQUEST, self::ERROR_REDIRECT_URI_MISMATCH, 'The redirect URI is mandatory and was not supplied.');
            }

            $redirectUri = current($client->getRedirectUris());

        } else {
            // Only need to validate if redirect_uri is provided on input and stored
            if (!$this->validateRedirectUri($redirectUri, $client->getRedirectUris())) {
                throw new OAuth2ServerException(self::HTTP_BAD_REQUEST, self::ERROR_REDIRECT_URI_MISMATCH, 'The redirect URI provided does not match registered URI(s).');
            }

        }

        return $redirectUri;
    }

    /**
     * Redirect the user appropriately after approval.
     *
     * After the user has approved or denied the access request the authorization server should call this function to
     * redirect the user appropriately.
     *
     * @param bool        $isAuthorized true or false depending on whether the user authorized the access.
     * @param mixed       $data         Application data
     * @param Request     $request
     * @param string|null $scope
     *
     * @throws OAuth2RedirectException
     *
     * @return Response
     * @see      http://tools.ietf.org/html/draft-ietf-oauth-v2-20#section-4
     *
     * @ingroup  oauth2_section_4
     */
    public function finishClientAuthorization($isAuthorized, $data = null, Request $request = null, $scope = null)
    {
        // In theory, this could be POSTed by a 3rd-party (because we are not
        // internally enforcing NONCEs, etc)
        $params = $this->getAuthorizeParams($request);

        /**
         * Associative array as below:
         *   - response_type: The requested response: an access token, an
         *     authorization code, or both.
         *   - client_id: The client identifier as described in Section 2.
         *   - redirect_uri: An absolute URI to which the authorization server
         *     will redirect the user-agent to when the end-user authorization
         *     step is completed.
         *   - scope: (optional) The scope of the access request expressed as a
         *     list of space-delimited strings.
         *   - state: (optional) An opaque value used by the client to maintain
         *     state between the request and callback.
         *
         * @var array
         */
        $params += array(
            'state' => null,
        );

        $result = array();

        if ($isAuthorized === false) {
            $method = $params["response_type"] == self::RESPONSE_TYPE_AUTH_CODE?self::TRANSPORT_QUERY:self::TRANSPORT_FRAGMENT;
            throw new OAuth2RedirectException($params["redirect_uri"], self::ERROR_USER_DENIED, "The user denied access to your application", $params["state"], $method);
        } else {
            if ($params["response_type"] === self::RESPONSE_TYPE_AUTH_CODE) {
                $result[self::TRANSPORT_QUERY]['state'] = $params["state"];
                $result[self::TRANSPORT_QUERY]["code"] = $this->createAuthCode(
                    $params["client"],
                    $data,
                    $params["redirect_uri"],
                    $scope
                );
            } elseif ($params["response_type"] === self::RESPONSE_TYPE_ACCESS_TOKEN) {
                $result[self::TRANSPORT_FRAGMENT]['state'] = $params["state"];
                $result[self::TRANSPORT_FRAGMENT] += $this->createAccessToken($params["client"], $data, $scope, null, false);
            }
        }

        return $this->createRedirectUriCallbackResponse($params["redirect_uri"], $result);
    }

    // Other/utility functions.

    /**
     * Returns redirect response
     *
     * Handle both redirect for success or error response.
     *
     * @param string $redirectUri An absolute URI to which the authorization server will redirect the user-agent to when the end-user authorization step is completed.
     * @param array  $params      Parameters to be pass though buildUri().
     *
     * @return Response
     * @ingroup oauth2_section_4
     */
    private function createRedirectUriCallbackResponse($redirectUri, $params)
    {
        return new Response('', 302, array(
            'Location' => $this->buildUri($redirectUri, $params),
        ));
    }

    /**
     * Build the absolute URI based on supplied URI and parameters.
     *
     * @param string $uri    An absolute URI.
     * @param array  $params Parameters to be append as GET.
     *
     * @return string An absolute URI with supplied parameters.
     *
     * @ingroup oauth2_section_4
     */
    private function buildUri($uri, $params)
    {
        $parse_url = parse_url($uri);

        // Add our params to the parsed uri
        foreach ($params as $k => $v) {
            if (isset($parse_url[$k])) {
                $parse_url[$k] .= "&" . http_build_query($v);
            } else {
                $parse_url[$k] = http_build_query($v);
            }
        }

        // Put humpty dumpty back together
        return
            ((isset($parse_url["scheme"])) ? $parse_url["scheme"] . "://" : "")
            . ((isset($parse_url["user"])) ? $parse_url["user"] . ((isset($parse_url["pass"])) ? ":" . $parse_url["pass"] : "") . "@" : "")
            . ((isset($parse_url["host"])) ? $parse_url["host"] : "")
            . ((isset($parse_url["port"])) ? ":" . $parse_url["port"] : "")
            . ((isset($parse_url["path"])) ? $parse_url["path"] : "")
            . ((isset($parse_url["query"])) ? "?" . $parse_url["query"] : "")
            . ((isset($parse_url["fragment"])) ? "#" . $parse_url["fragment"] : "");
    }

    /**
     * Handle the creation of access token, also issue refresh token if support.
     *
     * This belongs in a separate factory, but to keep it simple, I'm just keeping it here.
     *
     * @param IOAuth2Client $client
     * @param mixed         $data
     * @param string|null   $scope
     * @param int|null      $access_token_lifetime How long the access token should live in seconds
     * @param bool          $issue_refresh_token Issue a refresh tokeniIf true and the storage mechanism supports it
     * @param int|null      $refresh_token_lifetime How long the refresh token should life in seconds
     *
     * @return array
     *
     * @see     http://tools.ietf.org/html/draft-ietf-oauth-v2-20#section-5
     *
     * @ingroup oauth2_section_5
     */
    public function createAccessToken(IOAuth2Client $client, $data, $scope = null, $access_token_lifetime = null, $issue_refresh_token = true, $refresh_token_lifetime = null)
    {
        $token = array(
            "access_token" => $this->genAccessToken(),
            "expires_in" => ($access_token_lifetime ?: $this->getVariable(self::CONFIG_ACCESS_LIFETIME)),
            "token_type" => $this->getVariable(self::CONFIG_TOKEN_TYPE),
            "scope" => $scope,
        );

        $this->storage->createAccessToken(
            $token["access_token"],
            $client,
            $data,
            time() + ($access_token_lifetime ?: $this->getVariable(self::CONFIG_ACCESS_LIFETIME)),
            $scope
        );

        // Issue a refresh token also, if we support them
        if ($this->storage instanceof IOAuth2RefreshTokens && $issue_refresh_token === true) {
            $token["refresh_token"] = $this->genAccessToken();
            $this->storage->createRefreshToken(
                $token["refresh_token"],
                $client,
                $data,
                time() + ($refresh_token_lifetime ?: $this->getVariable(self::CONFIG_REFRESH_LIFETIME)),
                $scope
            );

            // If we've granted a new refresh token, expire the old one
            if (null !== $this->oldRefreshToken) {
                $this->storage->unsetRefreshToken($this->oldRefreshToken);
                $this->oldRefreshToken = null;
            }
        }

        if ($this->storage instanceof IOAuth2GrantCode) {
            if (null !== $this->usedAuthCode) {
                $this->storage->markAuthCodeAsUsed($this->usedAuthCode->getToken());
                $this->usedAuthCode = null;
            }
        }

        return $token;
    }

    /**
     * Handle the creation of auth code.
     *
     * This belongs in a separate factory, but to keep it simple, I'm just
     * keeping it here.
     *
     * @param IOAuth2Client $client      Client related to the access token.
     * @param mixed         $data
     * @param string        $redirectUri An absolute URI to which the authorization server will redirect the user-agent to when the end-user authorization step is completed.
     * @param string        $scope       (optional) Scopes to be stored in space-separated string.
     *
     * @return string
     * @ingroup oauth2_section_4
     */
    private function createAuthCode(IOAuth2Client $client, $data, $redirectUri, $scope = null)
    {
        $code = $this->genAuthCode();
        $this->storage->createAuthCode(
            $code,
            $client,
            $data,
            $redirectUri,
            time() + $this->getVariable(self::CONFIG_AUTH_LIFETIME),
            $scope
        );

        return $code;
    }

    /**
     * Generates an unique access token.
     *
     * Implementing classes may want to override this function to implement
     * other access token generation schemes.
     *
     * @return string An unique access token.
     *
     * @ingroup oauth2_section_4
     * @see     OAuth2::genAuthCode()
     */
    protected function genAccessToken()
    {
        if (@file_exists('/dev/urandom')) { // Get 100 bytes of random data
            $randomData = file_get_contents('/dev/urandom', false, null, 0, 100);
        } elseif (function_exists('openssl_random_pseudo_bytes')) { // Get 100 bytes of pseudo-random data
            $bytes = openssl_random_pseudo_bytes(100, $strong);
            if (true === $strong && false !== $bytes) {
                $randomData = $bytes;
            }
        }
        // Last resort: mt_rand
        if (empty($randomData)) { // Get 108 bytes of (pseudo-random, insecure) data
            $randomData = mt_rand() . mt_rand() . mt_rand() . uniqid(mt_rand(), true) . microtime(true) . uniqid(
                    mt_rand(),
                    true
                );
        }

        return rtrim(strtr(base64_encode(hash('sha256', $randomData)), '+/', '-_'), '=');
    }

    /**
     * Generates an unique auth code.
     *
     * Implementing classes may want to override this function to implement
     * other auth code generation schemes.
     *
     * @return string An unique auth code.
     *
     * @see     OAuth2::genAccessToken()
     *
     * @ingroup oauth2_section_4
     */
    protected function genAuthCode()
    {
        return $this->genAccessToken(); // let's reuse the same scheme for token generation
    }

    /**
     * Pull out the Authorization HTTP header and return it.
     * According to draft 20, standard basic authorization is the only
     * header variable required (this does not apply to extended grant types).
     *
     * Implementing classes may need to override this function if need be.
     *
     * @todo    We may need to re-implement pulling out apache headers to support extended grant types
     *
     * @param Request $request
     *
     * @return array An array of the basic username and password provided.
     *
     * @see     http://tools.ietf.org/html/draft-ietf-oauth-v2-20#section-2.4.1
     * @ingroup oauth2_section_2
     */
    protected function getAuthorizationHeader(Request $request)
    {
        return array(
            'PHP_AUTH_USER' => $request->server->get('PHP_AUTH_USER'),
            'PHP_AUTH_PW' => $request->server->get('PHP_AUTH_PW'),
        );
    }

    /**
     * Returns HTTP headers for JSON.
     *
     * @see     http://tools.ietf.org/html/draft-ietf-oauth-v2-20#section-5.1
     * @see     http://tools.ietf.org/html/draft-ietf-oauth-v2-20#section-5.2
     *
     * @return array
     *
     * @ingroup oauth2_section_5
     */
    private function getJsonHeaders()
    {
        $headers = $this->getVariable(self::CONFIG_RESPONSE_EXTRA_HEADERS, array());
        $headers += array(
            'Content-Type' => 'application/json',
            'Cache-Control' => 'no-store',
            'Pragma' => 'no-cache',
        );
        return $headers;
    }

    /**
     * Internal method for validating redirect URI supplied
     *
     * @param string       $inputUri
     * @param string|array $storedUris
     *
     * @return bool
     */
    protected function validateRedirectUri($inputUri, $storedUris)
    {
        if (!$inputUri || !$storedUris) {
            return false; // if either one is missing, assume INVALID
        }

        $parsed = parse_url($inputUri);

        if (!$parsed) {
            return false;
        }

        if (isset($parsed['path'])) {
            $path = urldecode($parsed['path']);
            // check for 'path traversal'
            if (preg_match('#/\.\.?(/|$)#', $path)) {
                return false;
            }
        }

        if (!is_array($storedUris)) {
            $storedUris = array($storedUris);
        }

        foreach ($storedUris as $storedUri) {
            if (strcasecmp(substr($inputUri, 0, strlen($storedUri)), $storedUri) === 0) {
                return true;
            }
        }

        return false;
    }
}
