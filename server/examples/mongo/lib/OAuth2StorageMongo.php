<?php

/**
 * @file
 * Sample OAuth2 Library Mongo DB Implementation.
 *
 */

require_once __DIR__.'/../../../../lib/OAuth2.php';
require_once __DIR__.'/../../../../lib/IOAuth2Storage.php';
require_once __DIR__.'/../../../../lib/IOAuth2GrantCode.php';
require_once __DIR__.'/../../../../lib/IOAuth2RefreshTokens.php';

/**
 * Mongo storage engine for the OAuth2 Library.
 */
class OAuth2StorageMongo implements IOAuth2GrantCode, IOAuth2RefreshTokens
{
    /**
     * Change this to something unique for your system
     * @var string
     */
    const SALT = 'CHANGE_ME!';

    const CONNECTION = 'mongodb://user:pass@mongoserver/mydb';
    const DB = 'mydb';

    /**
     * @var Mongo
     */
    private $db;

    /**
     * Implements OAuth2::__construct().
     */
    public function __construct(PDO $db)
    {
        $mongo = new Mongo(self::CONNECTION);
        $this->db = $mongo->selectDB(self::DB);
    }

    /**
     * Release DB connection during destruct.
     */
    public function __destruct()
    {
        $this->db = null; // Release db connection
    }

    /**
     * Handle PDO exceptional cases.
     */
    private function handleException($e)
    {
        echo 'Database error: '. $e->getMessage();
        exit;
    }

    /**
     * Little helper function to add a new client to the database.
     *
     * @param $client_id
     *   Client identifier to be stored.
     * @param $client_secret
     *   Client secret to be stored.
     * @param $redirect_uri
     *   Redirect URI to be stored.
     */
    public function addClient($client_id, $client_secret, $redirect_uri)
    {
        $this->db->clients->insert(array(
            "_id" => $client_id,
            "pw" => $this->hash($client_secret, $client_id),
            "redirect_uri" => $redirect_uri
        ));
    }

    /**
     * Implements IOAuth2Storage::checkClientCredentials().
     *
     */
    public function checkClientCredentials($client_id, $client_secret = null)
    {
        $client = $this->db->clients->findOne(array("_id" => $client_id, "pw" => $client_secret));

        return $this->checkPassword($client_secret, $result['client_secret'], $client_id);
    }

    /**
     * Implements IOAuth2Storage::getRedirectUri().
     */
    public function getClientDetails($client_id)
    {
        $result = $this->db->clients->findOne(array("_id" => $client_id), array("redirect_uri"));
    }

    /**
     * Implements IOAuth2Storage::getAccessToken().
     */
    public function getAccessToken($oauth_token)
    {
        return $this->db->tokens->findOne(array("_id" => $oauth_token));
    }

    /**
     * Implements IOAuth2Storage::setAccessToken().
     */
    public function setAccessToken($oauth_token, $client_id, $user_id, $expires, $scope = null)
    {
        $this->db->tokens->insert(array(
            "_id" => $oauth_token,
            "client_id" => $client_id,
            "expires" => $expires,
            "scope" => $scope
        ));
    }

    /**
     * @see IOAuth2Storage::getRefreshToken()
     */
    public function getRefreshToken($refresh_token)
    {
        return $this->getToken($refresh_token, true);
    }

    /**
     * @see IOAuth2Storage::setRefreshToken()
     */
    public function setRefreshToken($refresh_token, $client_id, $user_id, $expires, $scope = null)
    {
        return $this->setToken($refresh_token, $client_id, $user_id, $expires, $scope, true);
    }

    /**
     * @see IOAuth2Storage::unsetRefreshToken()
     */
    public function unsetRefreshToken($refresh_token)
    {
        try {
            $sql = 'DELETE FROM '.self::TABLE_TOKENS.' WHERE refresh_token = :refresh_token';
            $stmt = $this->db->prepare($sql);
            $stmt->bindParam(':refresh_token', $refresh_token, PDO::PARAM_STR);
            $stmt->execute();
        } catch (PDOException $e) {
            $this->handleException($e);
        }
    }

    /**
     * Implements IOAuth2Storage::getAuthCode().
     */
    public function getAuthCode($code)
    {
        $stored_code = $this->db->auth_codes->findOne(array("_id" => $code));

        return $stored_code !== null ? $stored_code : false;
    }

    /**
     * Implements IOAuth2Storage::setAuthCode().
     */
    public function setAuthCode($code, $client_id, $user_id, $redirect_uri, $expires, $scope = null)
    {
        $this->db->auth_codes->insert(array(
            "_id" => $code,
            "client_id" => $client_id,
            "redirect_uri" => $redirect_uri,
            "expires" => $expires,
            "scope" => $scope
        ));
    }

    /**
     * @see IOAuth2Storage::checkRestrictedGrantType()
     */
    public function checkRestrictedGrantType($client_id, $grant_type)
    {
        return true; // Not implemented
    }

    /**
     * Change/override this to whatever your own password hashing method is.
     *
     * @param  string $secret
     * @return string
     */
    protected function hash($client_secret, $client_id)
    {
        return hash('blowfish', $client_id.$client_secret.self::SALT);
    }

    /**
     * Checks the password.
     * Override this if you need to
     *
     * @param string $client_id
     * @param string $client_secret
     * @param string $actualPassword
     */
    protected function checkPassword($try, $client_secret, $client_id)
    {
        return $try == $this->hash($client_secret, $client_id);
    }
}
