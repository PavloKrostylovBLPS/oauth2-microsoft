<?php namespace Stevenmaguire\OAuth2\Client\Provider;

use League\OAuth2\Client\Provider\AbstractProvider;
use League\OAuth2\Client\Provider\Exception\IdentityProviderException;
use League\OAuth2\Client\Token\AccessToken;
use Psr\Http\Message\ResponseInterface;

class Microsoft extends AbstractProvider
{
  /**
   * Default scopes
   *
   * @var array
   */
  public $defaultScopes = ['openid', 'email', 'profile', 'User.Read'];

  /**
   * Default tenant
   *
   * @var string
   */
  protected $tenant = 'common';

  /**
   * Base url for authorization.
   *
   * @var string
   */
  protected $urlAuthorize = 'https://login.microsoftonline.com/{tenant}/oauth2/v2.0/authorize';

  /**
   * Base url for access token.
   *
   * @var string
   */
  protected $urlAccessToken = 'https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token';

  /**
   * Base url for resource owner.
   *
   * @var string
   */
  protected $urlResourceOwnerDetails = 'https://graph.microsoft.com/oidc/userinfo';

  /**
   * Get authorization url to begin OAuth flow
   *
   * @return string
   */
  public function getBaseAuthorizationUrl()
  {
    return str_replace('{tenant}', $this->tenant, $this->urlAuthorize);
  }

  /**
   * Get access token url to retrieve token
   *
   * @return string
   */
  public function getBaseAccessTokenUrl(array $params)
  {
    return str_replace('{tenant}', $this->tenant, $this->urlAccessToken);
  }

  /**
   * Get default scopes
   *
   * @return array
   */
  protected function getDefaultScopes()
  {
    return $this->defaultScopes;
  }

  /**
   * Returns the string that should be used to separate scopes when building
   * the URL for requesting an access token.
   *
   * @return string Scope separator, defaults to ','
   */
  protected function getScopeSeparator()
  {
    return ' ';
  }

  /**
   * Check a provider response for errors.
   *
   * @throws IdentityProviderException
   * @param  ResponseInterface $response
   * @return void
   */
  protected function checkResponse(ResponseInterface $response, $data)
  {
    if (isset($data['error'])) {
      $message = isset($data['error_description']) ? $data['error_description'] : $response->getReasonPhrase();
      if(isset($data['error']['message'])) {
        $message = $data['error']['message'];
      }
      throw new IdentityProviderException(
        $message,
        $response->getStatusCode(),
        $response
      );
    }
  }

  /**
   * Generate a user object from a successful user details request.
   *
   * @param array $response
   * @param null|AccessToken $token
   * @return MicrosoftResourceOwner
   */
  protected function createResourceOwner(array $response, AccessToken $token = null)
  {
    return new MicrosoftResourceOwner($response);
  }

  /**
   * Get provider url to fetch user details
   *
   * @param null|AccessToken $token
   * @return string
   */
  public function getResourceOwnerDetailsUrl(AccessToken $token = null)
  {
    return $this->urlResourceOwnerDetails;
  }

  /**
   * Returns the authorization headers used by this provider.
   *
   * Typically this is "Bearer" or "MAC". For more information see:
   * http://tools.ietf.org/html/rfc6749#section-7.1
   *
   * No default is provided, providers must overload this method to activate
   * authorization headers.
   *
   * @param  mixed|null $token Either a string or an access token instance
   * @return array
   */
  protected function getAuthorizationHeaders($token = null)
  {
    return [
      'Authorization' => 'Bearer ' . $token,
    ];
  }
}
