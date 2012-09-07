<?php

namespace OAuth2\Tests\Fixtures;

use OAuth2\IOAuth2GrantExtension;
use OAuth2\OAuth2;
use OAuth2\OAuth2StorageStub;
use OAuth2\OAuth2ServerException;
use OAuth2\Model\IOAuth2Client;

class OAuth2GrantExtensionStub extends OAuth2StorageStub implements IOAuth2GrantExtension
{
  protected $facebookIds = array();

  public function checkGrantExtension(IOAuth2Client $client, $uri, array $inputData, array $authHeaders)
  {
    if ('http://company.com/fb_access_token' !== $uri) {
      throw new OAuth2ServerException(OAuth2::HTTP_BAD_REQUEST, OAuth2::ERROR_UNSUPPORTED_GRANT_TYPE);
    }

    if (!isset($inputData['fb_access_token'])) {
      return false;
    }

    $fbAccessToken = $inputData['fb_access_token'];
    $fbId = $this->getFacebookIdFromFacebookAccessToken($fbAccessToken);

    return isset($this->facebookIds[$fbId]);
  }

  public function addFacebookId($id)
  {
    $this->facebookIds[$id] = $id;
  }

  /**
   * Let's assume a fb access token looks like "something_fbid"
   *
   * In real life, we would verify the access token is valid, and get the facebook_id of the
   * user via GET http://graph.facebook.com/me
   */
  protected function getFacebookIdFromFacebookAccessToken($fbAccessToken)
  {
    return substr($fbAccessToken, strpos($fbAccessToken, '_') + 1);
  }
}
