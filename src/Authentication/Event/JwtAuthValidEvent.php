<?php

/**
 * Class JwtAuthValidEvent.
 *
 * @package Drupal\jwt\Authentication\Provider
 */
class JwtAuthValidEvent extends JwtAuthBaseEvent {
  /**
   * Variable holding the user authenticated by the token in the payload.
   *
   * @var object
   */
  protected $user;

  /**
   * {@inheritdoc}
   */
  public function __construct(JwtJsonWebTokenInterface $token) {
    $this->user = drupal_anonymous_user();
    parent::__construct($token);
  }

  /**
   * Sets the authenticated user that will be used for this request.
   *
   * @param object $user
   *   A loaded user object.
   */
  public function setUser($user) {
    $this->user = $user;
  }

  /**
   * Returns a loaded user to use if the token is validated.
   *
   * @return object
   *   A loaded user object
   */
  public function getUser() {
    return $this->user;
  }

}
