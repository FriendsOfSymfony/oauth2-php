<?php

namespace OAuth2\Model;

interface IOAuth2Token {

    public function getClientId();

    public function getExpiresIn();
    public function hasExpired();

    public function getToken();

    public function getScope();

    public function getData();
}

