<?php

/**
 * Class JwtAuthIssuerController.
 *
 * @package Drupal\jwt_auth_issuer\Controller
 */
class JwtAuthIssuerController {

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
   * {@inheritdoc}
   */
  public static function create(ContainerInterface $container) {
    $auth = $container->get('jwt.authentication.jwt');
    return new static($auth);
  }

  /**
   * Generate.
   *
   * @return stdClass JSON response with token.
   */
  public function tokenResponse() {
    $response = new \stdClass();
    $token = $this->auth->generateToken();
    if ($token === FALSE) {
      $response->error = "Error. Please set a key in the JWT admin page.";
      return new JsonResponse($response, 500);
    }

    $response->token = $token;
    return new JsonResponse($response);
  }

}
