<?php

use JwtAuthGenerateEvent;

/**
 * Class JwtAuthIssuerSubscriber.
 *
 * @package Drupal\jwt_auth_issuer
 */
class JwtAuthIssuerSubscriber {

  /**
   * Sets the standard claims set for a JWT.
   *
   * @param \JwtAuthGenerateEvent $event
   *   The event.
   */
  public static function setStandardClaims(JwtAuthGenerateEvent $event) {
    $event->addClaim('iat', time());
    // @todo: make these more configurable.
    $event->addClaim('exp', strtotime('+1 hour'));
  }

  /**
   * Sets claims for a Drupal consumer on the JWT.
   *
   * @param \JwtAuthGenerateEvent $event
   *   The event.
   */
  public static function setDrupalClaims(JwtAuthGenerateEvent $event) {
    global $user;
    $event->addClaim(
      ['drupal', 'uid'],
      $user->uid
    );
  }

}
