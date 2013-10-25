<?php

namespace OAuth2\Tests\Fixtures;

use OAuth2\OAuth2;
use OAuth2\IOAuth2Storage;
use OAuth2\Model\IOAuth2Client;
use OAuth2\Tests\Model\OAuth2Client;
use OAuth2\Tests\Model\OAuth2AccessToken;
use OAuth2\Tests\Fixtures\OAuth2StorageStub;

/**
 * IOAuth2Storage stub for testing
 */
class OAuth2StorageStub implements IOAuth2Storage {

    private $clients = array();
    private $accessTokens = array();
    private $allowedGrantTypes = array(OAuth2::GRANT_TYPE_AUTH_CODE);

    public function addClient(OAuth2Client $client) {
        $this->clients[$client->getPublicId()] = $client;
    }

    public function getClient($client_id) {
        if (isset($this->clients[$client_id])) {
            return $this->clients[$client_id];
        }
    }

    public function getClients() {
        return $this->clients;
    }

    public function checkClientCredentials(IOAuth2Client $client, $client_secret = NULL) {
        return $client->checkSecret($client_secret);
    }

    public function createAccessToken($oauth_token, IOAuth2Client $client, $data, $expires, $scope = NULL) {

        $token = new OAuth2AccessToken($client->getPublicId(), $oauth_token, $expires, $scope, $data);
        $this->accessTokens[$oauth_token] = $token;
    }

    public function getAccessToken($oauth_token) {
        if (isset($this->accessTokens[$oauth_token])) {
            return $this->accessTokens[$oauth_token];
        }
    }

    public function getAccessTokens() {
        return $this->accessTokens;
    }

    public function getLastAccessToken() {
        return end($this->accessTokens);
    }

    public function setAllowedGrantTypes(array $types) {
        $this->allowedGrantTypes = $types;
    }

    public function checkRestrictedGrantType(IOAuth2Client $client, $grant_type) {
        return in_array($grant_type, $this->allowedGrantTypes);
    }
}

