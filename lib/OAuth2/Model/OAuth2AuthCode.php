<?php

namespace OAuth2\Model;

class OAuth2AuthCode extends OAuth2Token implements IOAuth2AuthCode {

    public function __construct($clientId, $token, $expiresAt = NULL, $scope = NULL, $data = NULL, $redirectUri = NULL) {
        parent::__construct($clientId, $token, $expiresAt, $scope, $data);
        $this->setRedirectUri($redirectUri);
    }

    public function setRedirectUri($uri) {
        $this->redirectUri = $uri;
    }

    public function getRedirectUri() {
        return $this->redirectUri;
    }
}

