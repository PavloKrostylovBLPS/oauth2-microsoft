<?php namespace Stevenmaguire\OAuth2\Client\Provider;

use League\OAuth2\Client\Provider\ResourceOwnerInterface;

class MicrosoftResourceOwner implements ResourceOwnerInterface
{
  /**
   * Raw response
   *
   * @var array
   */
  protected $response;

  /**
   * Creates new resource owner.
   *
   * @param array  $response
   */
  public function __construct(array $response = array())
  {
    $this->response = $response;
  }

  /**
   * Get user id
   *
   * @return string|null
   */
  public function getId()
  {
    return $this->response['id'] ?: null;
  }

  /**
   * Get user email
   *
   * @return string|null
   */
  public function getEmail()
  {
    return $this->response['email'] ?: null;
  }

  /**
   * Get user firstname
   *
   * @return string|null
   */
  public function getFirstname()
  {
    return $this->response['givenname'] ?: null;
  }

  /**
   * Get user lastname
   *
   * @return string|null
   */
  public function getLastname()
  {
    return $this->response['familyname'] ?: null;
  }

  /**
   * Get user name
   *
   * @return string|null
   */
  public function getName()
  {
    return $this->getFirstname() !== null && $this->getLastname() !== null ? $this->getFirstname().' '.$this->getLastname() : null;
  }

  /**
   * Return all of the owner details available as an array.
   *
   * @return array
   */
  public function toArray()
  {
    return $this->response;
  }
}
