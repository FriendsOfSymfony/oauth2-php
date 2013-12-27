<?php

/**
 * @file
 * Sample protected resource.
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
    $token = $oauth->getBearerToken();
    $oauth->verifyAccessToken($token);
} catch (OAuth2ServerException $oauthError) {
    $oauthError->sendHttpResponse();
}

// With a particular scope, you'd do:
// $oauth->verifyAccessToken("scope_name");

?>

<html>
    <head>
    <title>Hello!</title>
    </head>
    <body>
    <p>This is a secret.</p>
    </body>
</html>
