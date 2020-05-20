<?php

/**
 * Class JwtAuthBaseEvent.
 *
 * @package Drupal\jwt\Authentication\Event
 */
class JwtAuthBaseEvent {
  /**
   * The JsonWebToken.
   *
   * @var \JsonWebTokenInterface
   */
  protected $jwt;

  /**
   * Constructs a JwtAuthEvent with a JsonWebToken.
   *
   * @param \JsonWebTokenInterface $token
   *   A decoded JWT.
   */
  public function __construct(JsonWebTokenInterface $token) {
    $this->jwt = $token;
  }

  /**
   * Returns the JWT.
   *
   * @return \JsonWebTokenInterface
   *   Returns the token.
   */
  public function getToken() {
    return $this->jwt;
  }

}
