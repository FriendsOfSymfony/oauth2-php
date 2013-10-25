<?php

namespace OAuth2\Model;

use OAuth2\Model\IOAuth2Token;

class OAuth2Token implements IOAuth2Token {

    private $clientId;
    private $token;
    private $expiresAt;
    private $scope;
    private $data;

    public function __construct($clientId, $token, $expiresAt = NULL, $scope = NULL, $data = NULL) {
        $this->setClientId($clientId);
        $this->setToken($token);
        $this->setExpiresAt($expiresAt);
        $this->setScope($scope);
        $this->setData($data);
    }

    public function setClientId($id) {
        $this->clientId = $id;
    }

    public function getClientId() {
        return $this->clientId;
    }

    public function setExpiresAt($timestamp) {
        $this->expiresAt = $timestamp;
    }

    public function getExpiresIn() {
        if ($this->expiresAt) {
            return $this->expiresAt - time();
        } else {
            return PHP_INT_MAX;
        }
    }

    public function hasExpired() {
        return time() > $this->expiresAt;
    }

    public function setToken($token) {
        $this->token = $token;
    }

    public function getToken()
    {
        return $this->token;
    }

    public function setScope($scope) {
        $this->scope = $scope;
    }

    public function getScope()
    {
        return $this->scope;
    }

    public function setData($data) {
        $this->data = $data;
    }

    public function getData()
    {
        return $this->data;
    }
}

