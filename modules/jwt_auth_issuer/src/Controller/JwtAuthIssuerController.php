<?php

/**
 * Class JwtAuthIssuerController.
 *
 * @package Drupal\jwt_auth_issuer\Controller
 */
class JwtAuthIssuerController {

  /**
   * The static instance
   *
   * @var \JwtAuthIssuerController
   */
  private static $_instance = null;

  public static function get() {
    if(self::$_instance === null) {
      self::$_instance = new static(JwtAuth::get());
    }
    return self::$_instance;
  }

  /**
   * The JWT Auth Service.
   *
   * @var \JwtAuth
   */
  protected $auth;

  /**
   * @param \JwtAuth $auth
   *   The JWT auth service.
   */
  public function __construct(JwtAuth $auth) {
    $this->auth = $auth;
  }

  /**
   * Generate.
   *
   * @return stdClass JSON response with token.
   * @throws ServicesException
   */
  public function tokenResponse() {
    $response = new \stdClass();
    $token = $this->auth->generateToken();
    if ($token === FALSE) {
      services_error(t("Error. Please set a key in the JWT admin page."), 500);
    }

    $response->token = $token;
    return $response;
  }

}
