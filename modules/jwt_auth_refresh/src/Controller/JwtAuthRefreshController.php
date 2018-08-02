<?php

class JwtAuthRefreshController extends JwtAuthIssuerController {
  /**
   * JWT Transcoder.
   *
   * @var JwtTranscoderInterface
   */
  protected $jwtTranscoder;

  /**
   * Current request.
   *
   * @var array|null
   */
  protected $currentRequest;

  /**
   * @inheritDoc
   */
  public function __construct(JwtAuth $auth, JwtAuthRefreshTokensInterface $refreshTokens, JwtTranscoderInterface $jwtTranscoder) {
    parent::__construct($auth, $refreshTokens);
    $this->accountSwitcher = $accountSwitcher;
    $this->flood = $flood;
    $this->jwtTranscoder = $jwtTranscoder;
    $this->currentRequest = $requestStack->getCurrentRequest();
  }

  /**
   * @inheritDoc
   */
  public static function create(ContainerInterface $container) {
    return new static(
      $container->get('jwt.authentication.jwt'),
      $container->get('jwt_auth_refresh.tokens'),
      $container->get('account_switcher'),
      $container->get('flood'),
      $container->get('jwt.transcoder'),
      $container->get('request_stack')
    );
  }

  /**
   * Refresh controller.
   *
   * @param array $request
   * @return array JsonResponse
   */
  public function refresh(Request $request) {
    $owner = $this->getToken($request)->getOwner();
    // @todo - Better approach than switching?
    $this->accountSwitcher->switchTo($owner);
    $response = $this->tokenResponse();
    $this->accountSwitcher->switchBack();
    return $response;
  }

  /**
   * Retrieve the refresh token from the request.
   *
   * @param array $request
   * @return JwtRefreshTokenInterface|null
   */
  protected function getToken(Request $request) {
    $json = json_decode($request->getContent());
    try {
      $jti = $this->jwtTranscoder->decode($json->refresh_token)->getClaim('jti');
    }
    catch (JwtDecodeException $e) {
      return NULL;
    }
    $tokens = $this->entityTypeManager()->getStorage('jwt_refresh_token')->loadByProperties([
      'uuid' => $jti,
    ]);
    if ($tokens) {
      return reset($tokens);
    }
    return NULL;
  }

  /**
   * Access checker.
   *
   * @param array $request
   * @return array
   */
  public function access() {
    // We can't type-hint $request
    // @see https://www.drupal.org/node/2786941
    $result = AccessResult::allowed();
    try {
      $this->floodControl();
    }
    catch (\Exception $e) {
      $result = AccessResult::forbidden($e->getMessage());
    }
    if ($token = $this->getToken($this->currentRequest)) {
      $owner = $token->getOwner();
      if (!$owner->isActive()) {
        $result = AccessResult::forbidden('Account not active.');
      }

    }
    else {
      $result = AccessResult::forbidden('No token provided.');
    }
    if ($result->isForbidden()) {
      $this->flood->register('jwt_auth_refresh.failed_refresh_ip', $this->config('user.flood')->get('ip_window'));
    }
    return $result;
  }

}
