<?php

/**
 * @file
 * Sample token endpoint.
 *
 * Obviously not production-ready code, just simple and to the point.
 *
 * In reality, you'd probably use a nifty framework to handle most of the crud for you.
 */

use OAuth2\OAuth2;
use OAuth2\OAuth2ServerException;

require 'lib/bootstrap.php';

$oauth = new OAuth2(new OAuth2StoragePDO(newPDO()));
try {
    $response = $oauth->grantAccessToken();
    $response->send();
} catch (OAuth2ServerException $oauthError) {
    $oauthError->getHttpResponse()->send();
}
