<?php

use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\Exception\AccessDeniedHttpException;

/**
 * JWT Authentication Provider.
 */
class JwtAuth {

  /**
   * The static instance
   *
   * @var \JwtAuth
   */
  private static $_instance = null;

  public static function get() {
    if(self::$_instance === null) {
      self::$_instance = new static(jwt_get_transcoder());
    }
    return self::$_instance;
  }

  /**
   * The JWT Transcoder service.
   *
   * @var \JwtTranscoderInterface
   */
  protected $transcoder;

  /**
   * Constructs a HTTP basic authentication provider object.
   *
   * @param \JwtTranscoderInterface $transcoder
   *   The jwt transcoder service.
   */
  public function __construct(
    JwtTranscoderInterface $transcoder
  ) {
    $this->transcoder = $transcoder;
  }

  /**
   * {@inheritdoc}
   */
  public function applies(Request $request) {
    $auth = $request->headers->get('Authorization');
    return preg_match('/^Bearer .+/', $auth);
  }

  /**
   * {@inheritdoc}
   */
  public function authenticate(Request $request) {
    $raw_jwt = $this->getJwtFromRequest($request);
    if(!$raw_jwt) {
      //throw new AccessDeniedHttpException(t('No JWT token provided!'));
      return false; // try another authentication method
    }

    // Decode JWT and validate signature.
    try {
      $jwt = $this->transcoder->decode($raw_jwt);
    }
    catch (JwtDecodeException $e) {
      throw new AccessDeniedHttpException($e->getMessage(), $e);
    }

    $validate = new JwtAuthValidateEvent($jwt);
    // Signature is validated, but allow modules to do additional validation.
    drupal_alter('jwt_auth_validate', $validate);
    if (!$validate->isValid()) {
      throw new AccessDeniedHttpException($validate->invalidReason());
    }

    $valid = new JwtAuthValidEvent($jwt);
    drupal_alter('jwt_auth_valid', $valid);
    $user = $valid->getUser();

    if (!$user || !$user->uid) {
      throw new AccessDeniedHttpException('Unable to load user from provided JWT.');
    }

    return $user;
  }

  /**
   * Generate a new JWT token calling all event handlers.
   *
   * @return string|bool
   *   The encoded JWT token. False if there is a problem encoding.
   */
  public function generateToken() {
    global $user;
    if(!$user || !$user->uid) {
      services_error(t('No token can be issued for anonymous user'), 401);
    }
    $event = new JwtAuthGenerateEvent(new JsonWebToken());
    drupal_alter('jwt_auth_generate', $event);
    $jwt = $event->getToken();
    return $this->transcoder->encode($jwt);
  }

  /**
   * Gets a raw JsonWebToken from the current request.
   *
   * @param Request $request
   *   The request.
   *
   * @return string|bool
   *   Raw JWT String if on request, false if not.
   */
  protected function getJwtFromRequest(Request $request) {
    $auth_header = $request->headers->get('Authorization');
    $matches = [];
    if (!$hasJWT = preg_match('/^Bearer (.*)/', $auth_header, $matches)) {
      return FALSE;
    }

    return $matches[1];
  }

}
