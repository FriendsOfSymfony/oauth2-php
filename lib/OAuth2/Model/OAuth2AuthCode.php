<?php

namespace OAuth2\Model;

class OAuth2AuthCode extends OAuth2Token implements IOAuth2AuthCode {

    public function __construct($clientId, $token, $expiresAt = NULL, $scope = NULL, $data = NULL, $redirectUri = NULL, $used = false) {
        parent::__construct($clientId, $token, $expiresAt, $scope, $data);
        $this->setRedirectUri($redirectUri);
        $this->setUsed($used);
    }

    public function setRedirectUri($uri) {
        $this->redirectUri = $uri;
    }

    public function getRedirectUri() {
        return $this->redirectUri;
    }

    public function setUsed($used) {
        $this->used = $used;
    }

    public function isUsed()
    {
        return $this->used;
    }
}

