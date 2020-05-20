<?php

/**
 * Class JwtAuthGenerateEvent.
 *
 * @package Drupal\jwt\Authentication\Event
 */
class JwtAuthGenerateEvent extends JwtAuthBaseEvent {

  /**
   * Adds a claim to a JsonWebToken.
   *
   * @see \JsonWebTokenInterface::setClaim()
   */
  public function addClaim($claim, $value) {
    $this->jwt->setClaim($claim, $value);
  }

  /**
   * Removes a claim from a JsonWebToken.
   *
   * @see \JsonWebTokenInterface::unsetClaim()
   */
  public function removeClaim($claim) {
    $this->jwt->unsetClaim($claim);
  }

}
