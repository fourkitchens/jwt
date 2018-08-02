<?php

/**
 * Interface JwtRefreshTokenInterface.
 *
 * @package Drupal\jwt_auth_refresh
 */
interface JwtAuthRefreshTokenInterface {

  /**
   * Determine if the token is expired.
   *
   * @return bool
   *   TRUE if the token is expired.
   */
  public function isExpired();

}
