<?php

namespace Drupal\Tests\jwt\Kernel;

use Drupal\KernelTests\KernelTestBase;
use Drupal\Tests\user\Traits\UserCreationTrait;

/**
 * Tests JWT config schema.
 *
 * @group JWT
 */
class UserAuthTest extends KernelTestBase {
  use UserCreationTrait;

  /**
   * {@inheritdoc}
   */
  public static $modules = ['system', 'user', 'field', 'key', 'jwt', 'jwt_auth_issuer', 'jwt_auth_consumer', 'jwt_test'];

  /**
   * {@inheritdoc}
   */
  public function setUp() {
    parent::setUp();
    $this->installSchema('system', 'sequences');

    $this->installEntitySchema('user');

    $this->installConfig(['field', 'key', 'jwt', 'jwt_test']);
  }

  /**
   * Verify the authentication for a user.
   */
  public function testAuth() {
    $account = $this->createUser(['access content']);
    $this->setCurrentUser($account);
    $auth = $this->container->get('jwt.authentication.jwt');
    $token = $auth->generateToken();
    /** @var \Drupal\jwt\Transcoder\JwtTranscoderInterface $transcoder */
    $transcoder = $this->container->get('jwt.transcoder');
    $decoded_jwt = $transcoder->decode($token);
    $this->assertEqual($account->id(), $decoded_jwt->getClaim(['drupal', 'uid']));
  }

}
