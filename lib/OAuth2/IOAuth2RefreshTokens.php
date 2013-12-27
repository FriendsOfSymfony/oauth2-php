<?php

namespace OAuth2;

use OAuth2\Model\IOAuth2Client;
use OAuth2\Model\IOAuth2Token;

/**
 * Storage engines that want to support refresh tokens should implement this interface.
 *
 * @author Dave Rochwerger <catch.dave@gmail.com>
 *
 * @see    http://tools.ietf.org/html/draft-ietf-oauth-v2-20#section-6
 * @see    http://tools.ietf.org/html/draft-ietf-oauth-v2-20#section-1.5
 */
interface IOAuth2RefreshTokens extends IOAuth2Storage
{
    /**
     * Grant refresh access tokens.
     *
     * Retrieve the stored data for the given refresh token.
     * Required for OAuth2::GRANT_TYPE_REFRESH_TOKEN.
     *
     * @param string $refreshToken Refresh token string.
     *
     * @return IOAuth2Token
     *
     * @see     http://tools.ietf.org/html/draft-ietf-oauth-v2-20#section-6
     *
     * @ingroup oauth2_section_6
     */
    public function getRefreshToken($refreshToken);

    /**
     * Take the provided refresh token values and store them somewhere.
     *
     * This function should be the storage counterpart to getRefreshToken().
     * If storage fails for some reason, we're not currently checking for
     * any sort of success/failure, so you should bail out of the script
     * and provide a descriptive fail message.
     * Required for OAuth2::GRANT_TYPE_REFRESH_TOKEN.
     *
     * @param string        $refreshToken The refresh token string to be stored.
     * @param IOAuth2Client $client       The client associated with this refresh token.
     * @param mixed         $data         Application data associated with the refresh token, such as a User object.
     * @param int           $expires      The timestamp when the refresh token will expire.
     * @param string        $scope        (optional) Scopes to be stored in space-separated string.
     *
     * @ingroup oauth2_section_6
     */
    public function createRefreshToken($refreshToken, IOAuth2Client $client, $data, $expires, $scope = null);

    /**
     * Expire a used refresh token.
     *
     * This is not explicitly required in the spec, but is almost implied. After granting a new refresh token, the old
     * one is no longer useful and so should be forcibly expired in the data store so it can't be used again.
     * If storage fails for some reason, we're not currently checking for any sort of success/failure, so you should
     * bail out of the script and provide a descriptive fail message.
     *
     * @param string $refreshToken The refresh token string to expire.
     *
     * @ingroup oauth2_section_6
     */
    public function unsetRefreshToken($refreshToken);
}
