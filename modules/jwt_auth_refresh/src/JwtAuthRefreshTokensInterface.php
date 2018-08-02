<?php

interface JwtAuthRefreshTokensInterface {

  /**
   * Retrieve a refresh token for a user. If a valid token already exists,
   * return it.
   *
   * @param object $account
   * The user account.
   * @return JwtAuthRefreshToken
   *   The token.
   */
  public function retrieveForUser($account);

}
