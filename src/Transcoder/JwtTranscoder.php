<?php

use Firebase\JWT\JWT;

/**
 * Class JwtTranscoder.
 *
 * @package Drupal\jwt
 */
class JwtTranscoder implements JwtTranscoderInterface {

  /**
   * The firebase/php-jwt transcoder.
   *
   * @var \Firebase\JWT\JWT
   */
  protected $transcoder;

  /**
   * The allowed algorithms with which a JWT can be decoded.
   *
   * @var string
   */
  protected $algorithm;

  /**
   * The algorithm type we are using.
   *
   * @var string
   */
  protected $algorithmType;

  /**
   * The key used to encode/decode a JsonWebToken.
   *
   * @var string
   */
  protected $secret;

  /**
   * The PEM encoded private key used for signing RSA JWTs.
   *
   * @var string
   */
  protected $privateKey;

  /**
   * The PEM encoded public key used to verify signatures on RSA JWTs.
   *
   * @var string
   */
  protected $publicKey;

  /**
   * {@inheritdoc}
   */
  public static function getAlgorithmOptions() {
    return [
      'HS256' => 'HMAC using SHA-256 (HS256)',
      'HS384' => 'HMAC using SHA-384 (HS384)',
      'HS512' => 'HMAC using SHA-512 (HS512)',
      'RS256' => 'RSASSA-PKCS1-v1_5 using SHA-256 (RS256)',
    ];
  }

  /**
   * {@inheritdoc}
   */
  public static function getAlgorithmType($algorithm) {
    switch ($algorithm) {
      case 'HS256':
      case 'HS384':
      case 'HS512':
        return 'jwt_hs';

      case 'RS256':
        return 'jwt_rs';

      default:
        return NULL;
    }
  }

  /**
   * Constructs a new JwtTranscoder.
   *
   * @param \Firebase\JWT\JWT $php_jwt
   *   The JWT library object.
   */
  public function __construct(JWT $php_jwt) {
    $this->transcoder = $php_jwt;
    $key_id = variable_get('jwt_key_id');
    $this->setAlgorithm(variable_get('jwt_algorithm'));

    if ($key_id !== NULL) {
      $key = key_get_key($key_id);
      if ($key !== NULL) {
        $key_value = key_get_key_value($key);
        if ($this->algorithmType === 'jwt_hs') {
          // Symmetric algorithm so we set the secret.
          $this->setSecret($key_value);
        }
        elseif ($this->algorithmType === 'jwt_rs') {
          // Asymmetric algorithm so we set the private key.
          $this->setPrivateKey($key_value);
        }
      }
    }
  }

  /**
   * {@inheritdoc}
   */
  public function setSecret($secret) {
    $this->secret = $secret;
  }

  /**
   * {@inheritdoc}
   */
  public function setAlgorithm($algorithm) {
    $this->algorithm = $algorithm;
    $this->algorithmType = self::getAlgorithmType($algorithm);
  }

  /**
   * {@inheritdoc}
   */
  public function setPrivateKey($private_key, $derive_public_key = TRUE) {
    $key_context = openssl_pkey_get_private($private_key);
    $key_details = openssl_pkey_get_details($key_context);
    if ($key_details === FALSE || $key_details['type'] !== OPENSSL_KEYTYPE_RSA) {
      return FALSE;
    }

    $this->privateKey = $private_key;
    if ($derive_public_key) {
      $this->publicKey = $key_details['key'];
    }

    return TRUE;
  }

  /**
   * {@inheritdoc}
   */
  public function setPublicKey($public_key) {
    $key_context = openssl_pkey_get_public($public_key);
    $key_details = openssl_pkey_get_details($key_context);
    if ($key_details === FALSE || $key_details['type'] !== OPENSSL_KEYTYPE_RSA) {
      return FALSE;
    }

    $this->publicKey = $public_key;
    return TRUE;
  }

  /**
   * {@inheritdoc}
   */
  public function decode($jwt) {
    $key = $this->getKey('decode');
    $algorithms = array($this->algorithm);
    try {
      $token = JWT::decode($jwt, $key, $algorithms);
    }
    catch (\Exception $e) {
      throw JwtDecodeException::newFromException($e);
    }
    return new JwtJsonWebToken($token);
  }

  /**
   * {@inheritdoc}
   */
  public function encode(JwtJsonWebTokenInterface $jwt) {
    $key = $this->getKey('encode');
    // Refuse to encode if we don't have a key yet.
    if ($key === NULL) {
      return FALSE;
    }
    return JWT::encode($jwt->getPayload(), $key, $this->algorithm);
  }

  /**
   * Helper function to get the correct key based on operation.
   *
   * @param string $operation
   *   The operation being performed. One of: encode, decode.
   *
   * @return null|string
   *   Returns NULL if opteration is not found. Otherwise returns key.
   */
  protected function getKey($operation) {
    if ($this->algorithmType === 'jwt_hs') {
      return $this->secret;
    }
    if ($this->algorithmType === 'jwt_rs') {
      if ($operation === 'encode') {
        return $this->privateKey;
      }
      if ($operation === 'decode') {
        return $this->publicKey;
      }
    }
    return NULL;
  }

}
