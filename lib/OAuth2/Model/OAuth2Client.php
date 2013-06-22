<?php

namespace OAuth2\Model;

class OAuth2Client implements IOAuth2Client {

    private $id;
    private $redirectUris;
    private $secret;
    private $allowedGrantTypes;

    public function __construct($id, $secret = NULL, array $redirectUris = array(), array $allowedGrantTypes = array()) {
        $this->setPublicId($id);
        $this->setSecret($secret);
        $this->setRedirectUris($redirectUris);
        $this->setAllowedGrantTypes($allowedGrantTypes);
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

    public function setAllowedGrantTypes(array $grantTypes)
    {
        $this->allowedGrantTypes = $grantTypes;
    }

    public function getAllowedGrantTypes()
    {
        return $this->allowedGrantTypes;
    }
}

