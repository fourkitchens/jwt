<?php

/**
 * JWT Authentication Provider.
 */
class JwtAuth {

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

    // Decode JWT and validate signature.
    try {
      $jwt = $this->transcoder->decode($raw_jwt);
    }
    catch (JwtDecodeException $e) {
      throw new AccessDeniedHttpException($e->getMessage(), $e);
    }

    $validate = new JwtAuthValidateEvent($jwt);
    // Signature is validated, but allow modules to do additional validation.
    $this->eventDispatcher->dispatch(JwtAuthEvents::VALIDATE, $validate);
    if (!$validate->isValid()) {
      throw new AccessDeniedHttpException($validate->invalidReason());
    }

    $valid = new JwtAuthValidEvent($jwt);
    $this->eventDispatcher->dispatch(JwtAuthEvents::VALID, $valid);
    $user = $valid->getUser();

    if (!$user) {
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
    $event = new JwtAuthGenerateEvent(new JsonWebToken());
    $this->eventDispatcher->dispatch(JwtAuthEvents::GENERATE, $event);
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
