<?php

namespace OAuth2\Tests\Fixtures;

use OAuth2\OAuth2;
use OAuth2\Model\IOAuth2Client;
use OAuth2\Model\OAuth2AccessToken;
use OAuth2\IOAuth2Storage;

/**
 * IOAuth2Storage stub for testing
 */
class OAuth2StorageStub implements IOAuth2Storage
{
    private $clients = array();
    private $accessTokens = array();
    private $allowedGrantTypes = array(OAuth2::GRANT_TYPE_AUTH_CODE);

    public function addClient(IOAuth2Client $client)
    {
        $this->clients[$client->getPublicId()] = $client;
    }

    public function getClient($client_id)
    {
        if (isset($this->clients[$client_id])) {
            return $this->clients[$client_id];
        }
    }

    public function getClients()
    {
        return $this->clients;
    }

    public function checkClientCredentials(IOAuth2Client $client, $clientSecret = null)
    {
        return $client->checkSecret($clientSecret);
    }

    public function createAccessToken($oauthToken, IOAuth2Client $client, $data, $expires, $scope = null)
    {
        $token = new OAuth2AccessToken($client->getPublicId(), $oauthToken, $expires, $scope, $data);

        $this->accessTokens[$oauthToken] = $token;
    }

    public function getAccessToken($oauth_token)
    {
        if (isset($this->accessTokens[$oauth_token])) {
            return $this->accessTokens[$oauth_token];
        }
    }

    public function getAccessTokens()
    {
        return $this->accessTokens;
    }

    public function getLastAccessToken()
    {
        return end($this->accessTokens);
    }

    public function setAllowedGrantTypes(array $types)
    {
        $this->allowedGrantTypes = $types;
    }

    public function checkRestrictedGrantType(IOAuth2Client $client, $grantType)
    {
        return in_array($grantType, $this->allowedGrantTypes);
    }
}
