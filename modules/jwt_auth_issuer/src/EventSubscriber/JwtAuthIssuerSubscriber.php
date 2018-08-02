<?php

use JwtAuthEvents;
use JwtAuthGenerateEvent;

/**
 * Class JwtAuthIssuerSubscriber.
 *
 * @package Drupal\jwt_auth_issuer
 */
class JwtAuthIssuerSubscriber {

  /**
   * The current user.
   *
   * @var object
   */
  protected $currentUser;

  /**
   * Constructor.
   *
   * @param object $user
   *   The current user.
   */
  public function __construct($user) {
    $this->currentUser = $user;
  }

  /**
   * {@inheritdoc}
   */
  public static function getSubscribedEvents() {
    $events[JwtAuthEvents::GENERATE][] = ['setStandardClaims', 100];
    $events[JwtAuthEvents::GENERATE][] = ['setDrupalClaims', 99];
    return $events;
  }

  /**
   * Sets the standard claims set for a JWT.
   *
   * @param \JwtAuthGenerateEvent $event
   *   The event.
   */
  public function setStandardClaims(JwtAuthGenerateEvent $event) {
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
  public function setDrupalClaims(JwtAuthGenerateEvent $event) {
    $event->addClaim(
      ['drupal', 'uid'],
      $this->currentUser->id()
    );
  }

}
