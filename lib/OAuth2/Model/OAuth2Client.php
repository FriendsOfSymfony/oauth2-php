<?php

namespace OAuth2\Model;

class OAuth2Client implements IOAuth2Client {

    private $id;
    private $redirectUris;
    private $secret;

    public function __construct($id, $secret = NULL, array $redirectUris = array()) {
        $this->setPublicId($id);
        $this->setSecret($secret);
        $this->setRedirectUris($redirectUris);
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
}

