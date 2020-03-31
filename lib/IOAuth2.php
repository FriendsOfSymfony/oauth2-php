<?php

namespace OAuth2;

use OAuth2\Model\IOAuth2AccessToken;
use OAuth2\Model\IOAuth2Client;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * @author Originally written by Dmitrii Poddubnyi <dpoddubny@gmail.com>.
 */
interface IOAuth2
{
    /**
     * Returns a persistent variable.
     *
     * @param string $name The name of the variable to return.
     * @param mixed $default The default value to use if this variable has never been set.
     *
     * @return mixed   The value of the variable.
     */
    public function getVariable($name, $default = null);

    /**
     * Sets a persistent variable.
     *
     * @param string $name The name of the variable to set.
     * @param mixed $value The value to set.
     *
     * @return OAuth2 The application (for chained calls of this method)
     */
    public function setVariable($name, $value);

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
     * @return IOAuth2AccessToken Token
     *
     * @throws OAuth2AuthenticateException
     * @see     http://tools.ietf.org/html/draft-ietf-oauth-v2-20#section-7
     *
     * @ingroup oauth2_section_7
     */
    public function verifyAccessToken($tokenParam, $scope = null);

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
     * @param Request $request
     * @param bool $removeFromRequest
     *
     * @return string|null
     * @throws OAuth2AuthenticateException
     * @todo Should we enforce TLS/SSL in this function?
     *
     * @see  http://tools.ietf.org/html/draft-ietf-oauth-v2-bearer-08#section-2.1
     * @see  http://tools.ietf.org/html/draft-ietf-oauth-v2-bearer-08#section-2.2
     * @see  http://tools.ietf.org/html/draft-ietf-oauth-v2-bearer-08#section-2.3
     *
     */
    public function getBearerToken(Request $request = null, $removeFromRequest = false);

    /**
     * Grant or deny a requested access token.
     *
     * This would be called from the "/token" endpoint as defined in the spec.
     * Obviously, you can call your endpoint whatever you want.
     * Draft specifies that the authorization parameters should be retrieved from POST, but you can override to whatever method you like.
     *
     * @param Request $request (optional) The request
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
    public function grantAccessToken(Request $request = null);

    /**
     * Redirect the user appropriately after approval.
     *
     * After the user has approved or denied the access request the authorization server should call this function to
     * redirect the user appropriately.
     *
     * @param bool $isAuthorized true or false depending on whether the user authorized the access.
     * @param mixed $data Application data
     * @param Request $request
     * @param string|null $scope
     *
     * @return Response
     * @throws OAuth2RedirectException
     *
     * @see      http://tools.ietf.org/html/draft-ietf-oauth-v2-20#section-4
     *
     * @ingroup  oauth2_section_4
     */
    public function finishClientAuthorization($isAuthorized, $data = null, Request $request = null, $scope = null);

    /**
     * Handle the creation of access token, also issue refresh token if support.
     *
     * This belongs in a separate factory, but to keep it simple, I'm just keeping it here.
     *
     * @param IOAuth2Client $client
     * @param mixed $data
     * @param string|null $scope
     * @param int|null $access_token_lifetime How long the access token should live in seconds
     * @param bool $issue_refresh_token Issue a refresh tokeniIf true and the storage mechanism supports it
     * @param int|null $refresh_token_lifetime How long the refresh token should life in seconds
     *
     * @return array
     *
     * @see     http://tools.ietf.org/html/draft-ietf-oauth-v2-20#section-5
     *
     * @ingroup oauth2_section_5
     */
    public function createAccessToken(IOAuth2Client $client, $data, $scope = null, $access_token_lifetime = null, $issue_refresh_token = true, $refresh_token_lifetime = null);
}
