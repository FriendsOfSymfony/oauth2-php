<?php

namespace OAuth2\Tests\Fixtures;

use OAuth2\OAuth2;
use OAuth2\IOAuth2GrantExtension;
use OAuth2\OAuth2ServerException;
use OAuth2\Model\IOAuth2Client;
use OAuth2\Tests\Fixtures\OAuth2StorageStub;

class OAuth2GrantExtensionJwtBearer extends OAuth2StorageStub implements IOAuth2GrantExtension
{
    protected $sub = null;

    public function checkGrantExtension(IOAuth2Client $client, $uri, array $inputData, array $authHeaders)
    {
        if ('urn:ietf:params:oauth:grant-type:jwt-bearer' !== $uri) {
            throw new OAuth2ServerException(OAuth2::HTTP_BAD_REQUEST, OAuth2::ERROR_UNSUPPORTED_GRANT_TYPE);
        }

        if (!isset($inputData['jwt'])) {
            return false;
        }

        $jsonWebToken = $inputData['jwt'];
        $decodedJwtStruct = self::decodeJwt($jsonWebToken);

        // Check our JWT has a subject
        if (!isset($decodedJwtStruct['sub'])) {
            return false;
        }

        // Check the subject is the expected one
        if ($this->sub !== $decodedJwtStruct['sub']) {
            return false;
        }

        return array(
            'data' => $decodedJwtStruct,
        );
    }

    public function setExpectedSubject($sub)
    {
        $this->sub = $sub;
    }

    /**
     * Let's pretend a JWT is endoded and signed by wrapping it in -ENCODED-JWT-
     *
     * In real life, we would verify the JWT is valid, and get the subject from it after decoding
     *
     * @param string An encoded JWT string
     * @return array The decoded JWT struct
     */
    public static function decodeJwt($encodedJwt)
    {
        $decodedJwt = str_replace('-ENCODED-JWT-', '', $encodedJwt);
        return json_decode($decodedJwt, true);
    }

    /**
     * Let's pretend a JWT is endoded and signed by wrapping it in -ENCODED-JWT-
     *
     * In real life, we would verify the JWT is valid, and get the subject from it after decoding
     * 
     * @param array A struct to encode as a JWT
     * @return string The encoded JWT
     */
    public static function encodeJwt($decodedStruct)
    {
        $decodedJwt = json_encode($decodedStruct);
        $wrapper = '-ENCODED-JWT-';
        $encodedJwt = sprintf(
            '%s%s%s',
            $wrapper,
            $decodedJwt,
            $wrapper
        );
        return $encodedJwt;
    }
}
