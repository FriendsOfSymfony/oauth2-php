<?php

namespace OAuth2\Model;

interface IOAuth2AuthCode extends IOAuth2Token {

    public function getRedirectUri();
}

