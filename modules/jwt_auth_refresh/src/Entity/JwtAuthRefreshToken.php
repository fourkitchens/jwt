<?php

/**
 * @ContentEntityType(
 *   id = "jwt_refresh_token",
 *   label = @Translation("JWT Refresh Token"),
 *   base_table = "jwt_refresh_token",
 *   entity_keys = {
 *     "id" = "id",
 *     "uid" = "uid",
 *     "uuid" = "uuid",
 *   }
 * )
 */
class JwtAuthRefreshToken extends EntityDrupalWrapper implements JwtAuthRefreshTokenInterface {

  /**
   * Creates a new Jwt Refresh Token.
   *
   * @return JwtAuthRefreshToken
   *   The new token.
   */
  public function create() {
    return new self('jwt_refresh_token');
  }

  /**
   * @inheritDoc
   */
  public function isExpired() {
    return $this->get('expires')->value() < REQUEST_TIME;
  }

  /**
   * Default TTL.
   *
   * One week. 60 * 60 * 24 * 7
   */
  const TTL = 604800;

  /**
   * @inheritDoc
   */
  public static function baseFieldDefinitions(EntityTypeInterface $entity_type) {
    $fields = parent::baseFieldDefinitions($entity_type);
    $fields['uid'] = BaseFieldDefinition::create('entity_reference')
      ->setLabel(t('User'))
      ->setDescription(t('The associated user.'))
      ->setSetting('target_type', 'user')
      ->setDefaultValueCallback('Drupal\node\Entity\Node::getCurrentUserId')
      ->setDisplayConfigurable('form', TRUE);
    $fields['expires'] = BaseFieldDefinition::create('timestamp')
      ->setCardinality(1)
      ->setLabel(t('Expires'))
      ->setDefaultValueCallback('Drupal\jwt_auth_refresh\Entity\JwtRefreshToken::expires')
      ->setDescription(t('The time the token expires.'));
    return $fields;
  }

  /**
   * Generate default value for the expires time.
   *
   * @return string[]
   *   The expiration time.
   */
  public static function expires() {
    return array(REQUEST_TIME + self::TTL);
  }

  /**
   * {@inheritdoc}
   */
  public function getOwner() {
    return $this->get('uid')->entity;
  }

  /**
   * {@inheritdoc}
   */
  public function getOwnerId() {
    return $this->get('uid');
  }

  /**
   * {@inheritdoc}
   */
  public function setOwnerId($uid) {
    $this->set('uid', $uid);
    return $this;
  }

  /**
   * {@inheritdoc}
   */
  public function setOwner(\stdClass $account) {
    $this->set('uid', $account->id);
    return $this;
  }

}
