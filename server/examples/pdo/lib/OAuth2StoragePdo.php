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
use OAuth2\Model\IOAuth2Client;

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
     * @param string $clientId     Client identifier to be stored.
     * @param string $clientSecret Client secret to be stored.
     * @param string $redirectUri  Redirect URI to be stored.
     */
    public function addClient($clientId, $clientSecret, $redirectUri)
    {
        try {
            $clientSecret = $this->hash($clientSecret, $clientId);

            $sql = 'INSERT INTO '.self::TABLE_CLIENTS.' (client_id, client_secret, redirect_uri) VALUES (:client_id, :client_secret, :redirect_uri)';
            $stmt = $this->db->prepare($sql);
            $stmt->bindParam(':client_id', $clientId, PDO::PARAM_STR);
            $stmt->bindParam(':client_secret', $clientSecret, PDO::PARAM_STR);
            $stmt->bindParam(':redirect_uri', $redirectUri, PDO::PARAM_STR);
            $stmt->execute();
        } catch (PDOException $e) {
            $this->handleException($e);
        }
    }

    /**
     * Implements IOAuth2Storage::checkClientCredentials().
     *
     */
    public function checkClientCredentials(IOAuth2Client $clientId, $clientSecret = null)
    {
        try {
            $sql = 'SELECT client_secret FROM '.self::TABLE_CLIENTS.' WHERE client_id = :client_id';
            $stmt = $this->db->prepare($sql);
            $stmt->bindParam(':client_id', $clientId, PDO::PARAM_STR);
            $stmt->execute();

            $result = $stmt->fetch(PDO::FETCH_ASSOC);

            if ($clientSecret === null) {
                return $result !== false;
            }

            return $this->checkPassword($clientSecret, $result['client_secret'], $clientId);
        } catch (PDOException $e) {
            $this->handleException($e);
        }
    }

    /**
     * Implements IOAuth2Storage::getRedirectUri().
     */
    public function getClientDetails($clientId)
    {
        try {
            $sql = 'SELECT redirect_uri FROM '.self::TABLE_CLIENTS.' WHERE client_id = :client_id';
            $stmt = $this->db->prepare($sql);
            $stmt->bindParam(':client_id', $clientId, PDO::PARAM_STR);
            $stmt->execute();

            $result = $stmt->fetch(PDO::FETCH_ASSOC);

            if ($result === false)
                    return false;

            return isset($result['redirect_uri']) && $result['redirect_uri'] ? $result : null;
        } catch (PDOException $e) {
            $this->handleException($e);
        }
    }

    /**
     * Implements IOAuth2Storage::getAccessToken().
     */
    public function getAccessToken($oauth_token)
    {
        return $this->getToken($oauth_token, false);
    }

    /**
     * Implements IOAuth2Storage::setAccessToken().
     */
    public function setAccessToken($oauth_token, $client_id, $user_id, $expires, $scope = null)
    {
        $this->setToken($oauth_token, $client_id, $user_id, $expires, $scope, false);
    }

    /**
     * @see IOAuth2Storage::getRefreshToken()
     */
    public function getRefreshToken($refreshToken)
    {
        return $this->getToken($refreshToken, true);
    }

    /**
     * @see IOAuth2Storage::setRefreshToken()
     */
    public function setRefreshToken($refreshToken, $clientId, $userId, $expires, $scope = null)
    {
        return $this->setToken($refreshToken, $clientId, $userId, $expires, $scope, true);
    }

    /**
     * @see IOAuth2Storage::unsetRefreshToken()
     */
    public function unsetRefreshToken($refreshToken)
    {
        try {
            $sql = 'DELETE FROM '.self::TABLE_TOKENS.' WHERE refresh_token = :refresh_token';
            $stmt = $this->db->prepare($sql);
            $stmt->bindParam(':refresh_token', $refreshToken, PDO::PARAM_STR);
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

            return $result !== false ? $result : null;
        } catch (PDOException $e) {
            $this->handleException($e);
        }
    }

    /**
     * Implements IOAuth2Storage::setAuthCode().
     */
    public function setAuthCode($code, $clientId, $userId, $redirectUri, $expires, $scope = null)
    {
        try {
            $sql = 'INSERT INTO '.self::TABLE_CODES.' (code, client_id, user_id, redirect_uri, expires, scope) VALUES (:code, :client_id, :user_id, :redirect_uri, :expires, :scope)';
            $stmt = $this->db->prepare($sql);
            $stmt->bindParam(':code', $code, PDO::PARAM_STR);
            $stmt->bindParam(':client_id', $clientId, PDO::PARAM_STR);
            $stmt->bindParam(':user_id', $userId, PDO::PARAM_STR);
            $stmt->bindParam(':redirect_uri', $redirectUri, PDO::PARAM_STR);
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
    public function checkRestrictedGrantType(IOAuth2Client $client, $grantType)
    {
        return true; // Not implemented
    }

    /**
     * Creates a refresh or access token
     *
     * @param string $token     Access or refresh token id
     * @param string $clientId
     * @param mixed  $userId
     * @param int    $expires
     * @param string $scope
     * @param bool   $isRefresh
     */
    protected function setToken($token, $clientId, $userId, $expires, $scope, $isRefresh = true)
    {
        try {
            $tableName = $isRefresh ? self::TABLE_REFRESH :  self::TABLE_TOKENS;

            $sql = "INSERT INTO $tableName (oauth_token, client_id, user_id, expires, scope) VALUES (:token, :client_id, :user_id, :expires, :scope)";
            $stmt = $this->db->prepare($sql);
            $stmt->bindParam(':token', $token, PDO::PARAM_STR);
            $stmt->bindParam(':client_id', $clientId, PDO::PARAM_STR);
            $stmt->bindParam(':user_id', $userId, PDO::PARAM_STR);
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
     * @param bool   $isRefresh
     *
     * @return array|null
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

            return $result !== false ? $result : null;
        } catch (PDOException $e) {
            $this->handleException($e);
        }
    }

    /**
     * Change/override this to whatever your own password hashing method is.
     *
     * @param  string $clientSecret
     * @param  string $clientId
     *
     * @return string
     */
    protected function hash($clientSecret, $clientId)
    {
        return hash('sha1', $clientId.$clientSecret.$this->salt);
    }

    /**
     * Checks the password.
     * Override this if you need to
     *
     * @param string $try
     * @param string $clientSecret
     * @param string $clientId
     *
     * @return bool
     */
    protected function checkPassword($try, $clientSecret, $clientId)
    {
        return $clientSecret == $this->hash($try, $clientId);
    }
}
