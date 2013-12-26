<?php

namespace OAuth2\Model;

interface IOAuth2Client {

    public function getPublicId();
    public function getRedirectUris();

    public function getAccessTokenLifetime();
    public function getRefreshTokenLifetime();
    public function getAuthCodeLifetime();
    public function getEnforceState();
}

