<?php

namespace OAuth2\Model;

interface IOAuth2Client {

    public function getPublicId();
    public function getRedirectUris();

    public function getSupportedScopes();
    public function getDefaultScopes();
    public function getScopePolicy();
}

