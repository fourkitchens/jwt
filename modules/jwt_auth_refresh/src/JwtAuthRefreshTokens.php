<?php

class JwtAuthRefreshTokens implements JwtRefreshTokensInterface {

  /**
   * Transcoder.
   *
   * @var JwtTranscoderInterface
   */
  protected $transcoder;

  /**
   * @inheritDoc
   */
  public function __construct(JwtTranscoderInterface $jwtTranscoder) {
    $this->transcoder = $jwtTranscoder;
  }

  /**
   * {@inheritdoc}
   */
  public function retrieveForUser($account) {
    $token = JwtAuthRefreshToken::create([
      'uid' => $account->uid,
    ]);
    $token->save();
    $jwt = new JwtJsonWebToken((object) [
      'jti' => $token->get('uuid')->getString(),
      'exp' => $token->get('expires')->getString(),
    ]);
    return $this->transcoder->encode($jwt);
  }

}
