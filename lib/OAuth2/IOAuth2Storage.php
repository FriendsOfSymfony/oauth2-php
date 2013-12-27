<?php

namespace OAuth2;

use OAuth2\Model\IOAuth2Client;
use OAuth2\Model\IOAuth2AccessToken;

/**
 * All storage engines need to implement this interface in order to use OAuth2 server
 *
 * @author David Rochwerger <catch.dave@gmail.com>
 */
interface IOAuth2Storage
{
    /**
     * Get a client by its ID.
     *
     * @param string $clientId
     *
     * @return IOAuth2Client
     */
    public function getClient($clientId);

    /**
     * Make sure that the client credentials are valid.
     *
     * @param IOAuth2Client $client       The client for which to check credentials.
     * @param string        $clientSecret (optional) If a secret is required, check that they've given the right one.
     *
     * @return bool TRUE if the client credentials are valid, and MUST return FALSE if they aren't.
     *
     * @see     http://tools.ietf.org/html/draft-ietf-oauth-v2-20#section-3.1
     *
     * @ingroup oauth2_section_3
     */
    public function checkClientCredentials(IOAuth2Client $client, $clientSecret = null);

    /**
     * Look up the supplied oauth_token from storage.
     *
     * We need to retrieve access token data as we create and verify tokens.
     *
     * @param string $oauthToken The token string.
     *
     * @return IOAuth2AccessToken
     *
     * @ingroup oauth2_section_7
     */
    public function getAccessToken($oauthToken);

    /**
     * Store the supplied access token values to storage.
     *
     * We need to store access token data as we create and verify tokens.
     *
     * @param string        $oauthToken The access token string to be stored.
     * @param IOAuth2Client $client     The client associated with this refresh token.
     * @param mixed         $data       Application data associated with the refresh token, such as a User object.
     * @param int           $expires    The timestamp when the refresh token will expire.
     * @param string        $scope      (optional) Scopes to be stored in space-separated string.
     *
     * @ingroup oauth2_section_4
     */
    public function createAccessToken($oauthToken, IOAuth2Client $client, $data, $expires, $scope = null);

    /**
     * Check restricted grant types of corresponding client identifier.
     *
     * If you want to restrict clients to certain grant types, override this
     * function.
     *
     * @param IOAuth2Client $client    Client to check.
     * @param string        $grantType Grant type to check. One of the values contained in OAuth2::GRANT_TYPE_REGEXP.
     *
     * @return bool Returns true if the grant type is supported by this client identifier or false if it isn't.
     *
     * @ingroup oauth2_section_4
     */
    public function checkRestrictedGrantType(IOAuth2Client $client, $grantType);
}
