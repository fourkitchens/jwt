<?php

namespace Drupal\jwt_auth_consumer\EventSubscriber;

use Drupal\jwt\Authentication\Event\JwtAuthValidateEvent;
use Drupal\jwt\Authentication\Event\JwtAuthValidEvent;
use Drupal\jwt\Authentication\Event\JwtAuthEvents;

/**
 * Class JwtAuthConsumerSubscriber.
 *
 * @package Drupal\jwt_auth_consumer
 */
class JwtAuthConsumerSubscriber implements EventSubscriberInterface {

  /**
   * {@inheritdoc}
   */
  public static function getSubscribedEvents() {
    $events[JwtAuthEvents::VALIDATE][] = array('validate');
    $events[JwtAuthEvents::VALID][] = array('loadUser');

    return $events;
  }

  /**
   * Validates that a uid is present in the JWT.
   *
   * This validates the format of the JWT and validate the uid is a
   * valid uid in the system.
   *
   * @param \Drupal\jwt\Authentication\Event\JwtAuthValidateEvent $event
   *   A JwtAuth event.
   */
  public function validate(JwtAuthValidateEvent $event) {
    $token = $event->getToken();
    $uid = $token->getClaim(['drupal', 'uid']);
    if ($uid === NULL) {
      $event->invalidate('No Drupal uid was provided in the JWT payload.');
    }
    $user = user_load($uid);
    if ($user === NULL) {
      $event->invalidate('No UID exists.');
    }
  }

  /**
   * Load and set a Drupal user to be authentication based on the JWT's uid.
   *
   * @param \Drupal\jwt\Authentication\Event\JwtAuthValidEvent $event
   *   A JwtAuth event.
   */
  public function loadUser(JwtAuthValidEvent $event) {
    $token = $event->getToken();
    $uid = $token->getClaim(['drupal', 'uid']);
    $user = user_load($uid);
    $event->setUser($user);
  }

}
