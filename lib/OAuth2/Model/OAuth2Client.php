<?php

namespace OAuth2\Model;

class OAuth2Client implements IOAuth2Client {

    private $id;
    private $redirectUris;
    private $secret;

    private $access_token_lifetime;
    private $refresh_token_lifetime;
    private $authcode_lifetime;
    private $enforce_state;

    public function __construct($id, $secret = NULL, array $redirectUris = array(), $access_token_lifetime = null, $refresh_token_lifetime = null, $authcode_lifetime = null, $enforce_state = null) {
        
        $this->setPublicId($id)
             ->setSecret($secret)
             ->setRedirectUris($redirectUris)
             ->setAccessTokenLifetime($access_token_lifetime)
             ->setRefreshTokenLifetime($refresh_token_lifetime)
             ->setAuthCodeLifetime($authcode_lifetime)
             ->setEnforceState($enforce_state);
    }

    public function setPublicId($id) {
        $this->id = $id;

        return $this;
    }

    public function getPublicId() {
        return $this->id;
    }

    public function setSecret($secret) {
        $this->secret = $secret;

        return $this;
    }

    public function checkSecret($secret) {
        return $this->secret === NULL || $secret === $this->secret;
    }

    public function setRedirectUris(array $redirectUris) {
        $this->redirectUris = $redirectUris;

        return $this;
    }

    public function getRedirectUris() {
        return $this->redirectUris;
    }

    public function setAccessTokenLifetime($access_token_lifetime) {
        $this->access_token_lifetime = $access_token_lifetime;

        return $this;
    }

    public function getAccessTokenLifetime() {

        return $this->access_token_lifetime;
    }

    public function setRefreshTokenLifetime($refresh_token_lifetime) {
        $this->refresh_token_lifetime = $refresh_token_lifetime;

        return $this;
    }

    public function getRefreshTokenLifetime() {

        return $this->refresh_token_lifetime;
    }

    public function setAuthCodeLifetime($authcode_lifetime) {
        $this->authcode_lifetime = $authcode_lifetime;

        return $this;
    }

    public function getAuthCodeLifetime() {

        return $this->authcode_lifetime;
    }

    public function setEnforceState($enforce_state) {
        $this->enforce_state = $enforce_state;

        return $this;
    }

    public function getEnforceState() {

        return $this->enforce_state;
    }
}

