<?php

namespace OAuth2\TokenGenerator;

use OAuth2\Model\IOAuth2Client;

interface TokenGeneratorInterface
{
    public function genAccessToken(IOAuth2Client $client, $data, $scope = null, $access_token_lifetime = null, $issue_refresh_token = true, $refresh_token_lifetime = null);

    public function genRefreshToken(IOAuth2Client $client, $data, $scope = null, $access_token_lifetime = null, $issue_refresh_token = true, $refresh_token_lifetime = null);

    public function genAuthCode(IOAuth2Client $client, $data, $scope = null, $redirectUri = null);
}
