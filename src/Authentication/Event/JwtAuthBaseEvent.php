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
   * @var \JwtJsonWebTokenInterface
   */
  protected $jwt;

  /**
   * Whether no further event listeners should be triggered.
   *
   * @var bool
   */
  private $propagationStopped = FALSE;

  /**
   * Constructs a JwtAuthEvent with a JsonWebToken.
   *
   * @param \JwtJsonWebTokenInterface $token
   *   A decoded JWT.
   */
  public function __construct(JwtJsonWebTokenInterface $token) {
    $this->jwt = $token;
  }

  /**
   * Returns the JWT.
   *
   * @return \JwtJsonWebTokenInterface
   *   Returns the token.
   */
  public function getToken() {
    return $this->jwt;
  }

  /**
   * Stops the propagation of the event to further event listeners.
   *
   * If multiple event listeners are connected to the same event, no
   * further event listener will be triggered once any trigger calls
   * stopPropagation().
   *
   * @api
   */
  public function stopPropagation() {
    $this->propagationStopped = TRUE;
  }

}
