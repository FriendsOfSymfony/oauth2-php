<?php

namespace OAuth2;

use OAuth2\Model\IOAuth2Client;
use OAuth2\Model\IOAuth2AuthCode;

/**
 * Storage engines that support the "Authorization Code" grant type should implement this interface
 *
 * @author Dave Rochwerger <catch.dave@gmail.com>
 *
 * @see    http://tools.ietf.org/html/draft-ietf-oauth-v2-20#section-4.1
 */
interface IOAuth2GrantCode extends IOAuth2Storage
{
    /**
     * The Authorization Code grant type supports a response type of "code".
     *
     * @var string
     * @see http://tools.ietf.org/html/draft-ietf-oauth-v2-20#section-1.4.1
     * @see http://tools.ietf.org/html/draft-ietf-oauth-v2-20#section-4.2
     */
    const RESPONSE_TYPE_CODE = OAuth2::RESPONSE_TYPE_AUTH_CODE;

    /**
     * Fetch authorization code data (probably the most common grant type).
     *
     * Retrieve the stored data for the given authorization code.
     * Required for OAuth2::GRANT_TYPE_AUTH_CODE.
     *
     * @param string $code The authorization code string for which to fetch data.
     *
     * @return IOAuth2AuthCode
     *
     * @see     http://tools.ietf.org/html/draft-ietf-oauth-v2-20#section-4.1
     *
     * @ingroup oauth2_section_4
     */
    public function getAuthCode($code);

    /**
     * Take the provided authorization code values and store them somewhere.
     *
     * This function should be the storage counterpart to getAuthCode().
     * If storage fails for some reason, we're not currently checking for any sort of success/failure, so you should
     * bail out of the script and provide a descriptive fail message.
     * Required for OAuth2::GRANT_TYPE_AUTH_CODE.
     *
     * @param string        $code        Authorization code string to be stored.
     * @param IOAuth2Client $client      The client associated with this authorization code.
     * @param mixed         $data        Application data to associate with this authorization code, such as a User object.
     * @param string        $redirectUri Redirect URI to be stored.
     * @param int           $expires     The timestamp when the authorization code will expire.
     * @param string        $scope       l(optional) Scopes to be stored in space-separated string.
     *
     * @ingroup oauth2_section_4
     */
    public function createAuthCode($code, IOAuth2Client $client, $data, $redirectUri, $expires, $scope = null);

    /**
     * Marks auth code as expired.
     *
     * Depending on implementation it can change expiration date on auth code or remove it at all.
     *
     * @param string $code
     */
    public function markAuthCodeAsUsed($code);
}
