<?php

namespace OAuth2\Model;

class OAuth2Client implements IOAuth2Client {

    private $id;
    private $redirectUris;
    private $secret;

    private $default_scopes;
    private $scope_policy;

    public function __construct($id, $secret = NULL, array $redirectUris = array(), $scope_policy = null, $default_scopes = null) {
        $this->setPublicId($id);
        $this->setSecret($secret);
        $this->setRedirectUris($redirectUris);

        $this->setScopePolicy($scope_policy);
        $this->setDefaultScopes($default_scopes);
    }

    public function setPublicId($id) {
        $this->id = $id;
    }

    public function getPublicId() {
        return $this->id;
    }

    public function setSecret($secret) {
        $this->secret = $secret;
    }

    public function checkSecret($secret) {
        return $this->secret === NULL || $secret === $this->secret;
    }

    public function setRedirectUris(array $redirectUris) {
        $this->redirectUris = $redirectUris;
    }

    public function getRedirectUris() {
        return $this->redirectUris;
    }


    public function setDefaultScopes($default_scopes) {
        $this->default_scopes = $default_scopes;
    }

    public function getDefaultScopes() {
        return $this->default_scopes;
    }

    public function setScopePolicy($scope_policy) {
        $this->scope_policy = $scope_policy;
    }

    public function getScopePolicy() {
        return $this->scope_policy;
    }
}

