<?php

/**
 * @file
 * Sample OAuth2 Library PDO DB Implementation.
 *
 * Simply pass in a configured PDO class, eg:
 *   new PDOOAuth2( new PDO('mysql:dbname=mydb;host=localhost', 'user', 'pass') );
 */

use OAuth2\IOAuth2GrantCode;
use OAuth2\IOAuth2RefreshTokens;

/**
 * PDO storage engine for the OAuth2 Library.
 */
class OAuth2StoragePdo implements IOAuth2GrantCode, IOAuth2RefreshTokens
{
    /**@#+
     * Centralized table names
     *
     * @var string
     */
    const TABLE_CLIENTS = 'clients';
    const TABLE_CODES   = 'auth_codes';
    const TABLE_TOKENS  = 'access_tokens';
    const TABLE_REFRESH = 'refresh_tokens';
    /**@#-*/

    /**
     * @var PDO
     */
    private $db;

    /**
     * @var string
     */
    private $salt;

    /**
     * Implements OAuth2::__construct().
     */
    public function __construct(PDO $db, $salt = 'CHANGE_ME!')
    {
        $this->db = $db;
    }

    /**
     * Handle PDO exceptional cases.
     */
    private function handleException($e)
    {
        throw $e;
    }

    /**
     * Little helper function to add a new client to the database.
     *
     * Do NOT use this in production! This sample code stores the secret
     * in plaintext!
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
        try {
            $client_secret = $this->hash($client_secret, $client_id);

            $sql = 'INSERT INTO '.self::TABLE_CLIENTS.' (client_id, client_secret, redirect_uri) VALUES (:client_id, :client_secret, :redirect_uri)';
            $stmt = $this->db->prepare($sql);
            $stmt->bindParam(':client_id', $client_id, PDO::PARAM_STR);
            $stmt->bindParam(':client_secret', $client_secret, PDO::PARAM_STR);
            $stmt->bindParam(':redirect_uri', $redirect_uri, PDO::PARAM_STR);
            $stmt->execute();
        } catch (PDOException $e) {
            $this->handleException($e);
        }
    }

    /**
     * Implements IOAuth2Storage::checkClientCredentials().
     *
     */
    public function checkClientCredentials($client_id, $client_secret = NULL)
    {
        try {
            $sql = 'SELECT client_secret FROM '.self::TABLE_CLIENTS.' WHERE client_id = :client_id';
            $stmt = $this->db->prepare($sql);
            $stmt->bindParam(':client_id', $client_id, PDO::PARAM_STR);
            $stmt->execute();

            $result = $stmt->fetch(PDO::FETCH_ASSOC);

            if ($client_secret === NULL)
                    return $result !== FALSE;

            return $this->checkPassword($client_secret, $result['client_secret'], $client_id);
        } catch (PDOException $e) {
            $this->handleException($e);
        }
    }

    /**
     * Implements IOAuth2Storage::getRedirectUri().
     */
    public function getClientDetails($client_id)
    {
        try {
            $sql = 'SELECT redirect_uri FROM '.self::TABLE_CLIENTS.' WHERE client_id = :client_id';
            $stmt = $this->db->prepare($sql);
            $stmt->bindParam(':client_id', $client_id, PDO::PARAM_STR);
            $stmt->execute();

            $result = $stmt->fetch(PDO::FETCH_ASSOC);

            if ($result === FALSE)
                    return FALSE;

            return isset($result['redirect_uri']) && $result['redirect_uri'] ? $result : NULL;
        } catch (PDOException $e) {
            $this->handleException($e);
        }
    }

    /**
     * Implements IOAuth2Storage::getAccessToken().
     */
    public function getAccessToken($oauth_token)
    {
        return $this->getToken($oauth_token, FALSE);
    }

    /**
     * Implements IOAuth2Storage::setAccessToken().
     */
    public function setAccessToken($oauth_token, $client_id, $user_id, $expires, $scope = NULL)
    {
        $this->setToken($oauth_token, $client_id, $user_id, $expires, $scope, FALSE);
    }

    /**
     * @see IOAuth2Storage::getRefreshToken()
     */
    public function getRefreshToken($refresh_token)
    {
        return $this->getToken($refresh_token, TRUE);
    }

    /**
     * @see IOAuth2Storage::setRefreshToken()
     */
    public function setRefreshToken($refresh_token, $client_id, $user_id, $expires, $scope = NULL)
    {
        return $this->setToken($refresh_token, $client_id, $user_id, $expires, $scope, TRUE);
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
        try {
            $sql = 'SELECT code, client_id, user_id, redirect_uri, expires, scope FROM '.self::TABLE_CODES.' auth_codes WHERE code = :code';
            $stmt = $this->db->prepare($sql);
            $stmt->bindParam(':code', $code, PDO::PARAM_STR);
            $stmt->execute();

            $result = $stmt->fetch(PDO::FETCH_ASSOC);

            return $result !== FALSE ? $result : NULL;
        } catch (PDOException $e) {
            $this->handleException($e);
        }
    }

    /**
     * Implements IOAuth2Storage::setAuthCode().
     */
    public function setAuthCode($code, $client_id, $user_id, $redirect_uri, $expires, $scope = NULL)
    {
        try {
            $sql = 'INSERT INTO '.self::TABLE_CODES.' (code, client_id, user_id, redirect_uri, expires, scope) VALUES (:code, :client_id, :user_id, :redirect_uri, :expires, :scope)';
            $stmt = $this->db->prepare($sql);
            $stmt->bindParam(':code', $code, PDO::PARAM_STR);
            $stmt->bindParam(':client_id', $client_id, PDO::PARAM_STR);
            $stmt->bindParam(':user_id', $user_id, PDO::PARAM_STR);
            $stmt->bindParam(':redirect_uri', $redirect_uri, PDO::PARAM_STR);
            $stmt->bindParam(':expires', $expires, PDO::PARAM_INT);
            $stmt->bindParam(':scope', $scope, PDO::PARAM_STR);

            $stmt->execute();
        } catch (PDOException $e) {
            $this->handleException($e);
        }
    }

    /**
     * @see IOAuth2Storage::checkRestrictedGrantType()
     */
    public function checkRestrictedGrantType($client_id, $grant_type)
    {
        return TRUE; // Not implemented
    }

    /**
     * Creates a refresh or access token
     *
     * @param string $token - Access or refresh token id
     * @param string $client_id
     * @param mixed $user_id
     * @param int $expires
     * @param string $scope
     * @param bool $isRefresh
     */
    protected function setToken($token, $client_id, $user_id, $expires, $scope, $isRefresh = TRUE)
    {
        try {
            $tableName = $isRefresh ? self::TABLE_REFRESH :  self::TABLE_TOKENS;

            $sql = "INSERT INTO $tableName (oauth_token, client_id, user_id, expires, scope) VALUES (:token, :client_id, :user_id, :expires, :scope)";
            $stmt = $this->db->prepare($sql);
            $stmt->bindParam(':token', $token, PDO::PARAM_STR);
            $stmt->bindParam(':client_id', $client_id, PDO::PARAM_STR);
            $stmt->bindParam(':user_id', $user_id, PDO::PARAM_STR);
            $stmt->bindParam(':expires', $expires, PDO::PARAM_INT);
            $stmt->bindParam(':scope', $scope, PDO::PARAM_STR);

            $stmt->execute();
        } catch (PDOException $e) {
            $this->handleException($e);
        }
    }

    /**
     * Retrieves an access or refresh token.
     *
     * @param string $token
     * @param bool $refresh
     */
    protected function getToken($token, $isRefresh = true)
    {
        try {
            $tableName = $isRefresh ? self::TABLE_REFRESH :  self::TABLE_TOKENS;
            $tokenName = $isRefresh ? 'refresh_token' : 'oauth_token';

            $sql = "SELECT oauth_token AS $tokenName, client_id, expires, scope, user_id FROM $tableName WHERE oauth_token = :token";
            $stmt = $this->db->prepare($sql);
            $stmt->bindParam(':token', $token, PDO::PARAM_STR);
            $stmt->execute();

            $result = $stmt->fetch(PDO::FETCH_ASSOC);

            return $result !== FALSE ? $result : NULL;
        } catch (PDOException $e) {
            $this->handleException($e);
        }
    }

    /**
     * Change/override this to whatever your own password hashing method is.
     *
     * @param string $secret
     * @return string
     */
    protected function hash($client_secret, $client_id)
    {
        return hash('sha1', $client_id.$client_secret.$this->salt);
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
        return $client_secret == $this->hash($try, $client_id);
    }
}
