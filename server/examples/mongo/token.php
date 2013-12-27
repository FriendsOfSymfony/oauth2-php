<?php

/**
 * @file
 * Sample token endpoint.
 *
 * Obviously not production-ready code, just simple and to the point.
 *
 * In reality, you'd probably use a nifty framework to handle most of the crud for you.
 */

require 'lib/MongoOAuth2.php';

$oauth = new MongoOAuth2();
try {
    $oauth->grantAccessToken();
} catch (OAuth2ServerException $oauthError) {
    $oauthError->sendHttpResponse();
}
