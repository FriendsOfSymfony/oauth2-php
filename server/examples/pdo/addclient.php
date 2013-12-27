<?php

/**
 * @file
 * Sample client add script.
 *
 * Obviously not production-ready code, just simple and to the point.
 */

require 'lib/bootstrap.php';

if ($_POST && isset($_POST["client_id"]) && isset($_POST["client_secret"]) && isset($_POST["redirect_uri"])) {
    $oauth = new OAuth2StoragePDO(newPDO());
    $oauth->addClient($_POST["client_id"], $_POST["client_secret"], $_POST["redirect_uri"]);
}

?>

<html>
    <head>
        <title>Add Client</title>
    </head>
    <body>
        <form method="post" action="addclient.php">
            <p>
                <label for="client_id">Client ID:</label>
                <input type="text" name="client_id" id="client_id" />
            </p>
            <p>
                <label for="client_secret">Client Secret (password/key):</label>
                <input type="text" name="client_secret" id="client_secret" />
            </p>
            <p>
                <label for="redirect_uri">Redirect URI:</label>
                <input type="text" name="redirect_uri" id="redirect_uri" />
            </p>
            <input type="submit" value="Submit" />
        </form>
    </body>
</html>
