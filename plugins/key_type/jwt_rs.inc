<?php

/**
 * @file
 * Plugin definition for the JWT RSA key type.
 */

$plugin = array(
  'label' => t('JWT RSA Key'),
  'description' => t('A key type used for JWT RSA signature algorithms.'),
  'group' => 'privatekey',
  'key value' => array(
    'plugin' => 'textarea_field',
  ),
  'default configuration' => 'jwt_key_type_rs_defaults',
  'build configuration form' => 'jwt_key_type_rs_form',
  'generate key value' => 'jwt_key_type_rs_generate',
  'validate key value' => 'jwt_key_type_rs_validate',
);

/**
 * Returns the default configuration for JWT RSA.
 *
 * @return array
 *   The default form configuration.
 */
function jwt_key_type_rs_defaults() {
  return array(
    'algorithm' => 'RS256',
  );
}


/**
 * Build the plugin configuration form.
 *
 * @param array $form
 *   The Drupal form array.
 * @param array &$form_state
 *   The Drupal form state array.
 *
 * @return array
 *   The plugin configuration form.
 */
function jwt_key_type_rs_form(array $form, array &$form_state) {
  $config = $form_state['storage']['key_config'] + jwt_key_type_rs_defaults();
  $algorithm_options = array(
    'RS256' => t('RSASSA-PKCS1-v1_5 using SHA-256 (RS256)'),
  );

  $algorithm = $config['algorithm'];

  $form['algorithm'] = array(
    '#type' => 'select',
    '#title' => t('JWT Algorithm'),
    '#description' => t('The JWT Algorithm to use with this key.'),
    '#options' => $algorithm_options,
    '#default_value' => $algorithm,
    '#required' => TRUE,
  );

  return $form;
}

/**
 * Get key sizes for the various algorithms.
 *
 * @return array
 *   An array key key sizes.
 */
function jwt_key_type_rs_get_algorithm_key_size() {
  return array(
    'RS256' => 2048,
  );
}

/**
 * Generate a key value.
 *
 * @param array $config
 *   The key configuration.
 *
 * @return string
 *   A random key.
 */
function jwt_key_type_rs_generate(array $config) {
  $algorithm_keysize = jwt_key_type_rs_get_algorithm_key_size();
  $algorithm = $config['algorithm'];
  if (empty($algorithm) || !isset($algorithm_keysize[$algorithm])) {
    $algorithm = 'RS256';
  }

  $key_resource = openssl_pkey_new(array(
    'private_key_bits' => $algorithm_keysize[$algorithm],
    'private_key_type' => OPENSSL_KEYTYPE_RSA,
  ));
  $key_string = '';
  openssl_pkey_export($key_resource, $key_string);
  openssl_pkey_free($key_resource);

  return $key_string;
}

/**
 * Validate the key value.
 *
 * @param array $form
 *   The Drupal form array.
 * @param array &$form_state
 *   The Drupal form state array.
 * @param string $key_value
 *   The key value to validate.
 */
function jwt_key_type_rs_validate(array $form, array &$form_state, $key_value) {
  if (!$form_state['values']['algorithm']) {
    return;
  }

  // Validate the key.
  $algorithm = $form_state['values']['algorithm'];

  $key_resource = openssl_pkey_get_private($key_value);
  if ($key_resource === FALSE) {
    form_set_error('algorithm', t('Invalid Private Key.'));
  }

  $key_details = openssl_pkey_get_details($key_resource);
  if ($key_details === FALSE) {
    form_set_error('algorithm', t('Unable to get private key details.'));
  }

  $required_bits = jwt_key_type_rs_get_algorithm_key_size()[$algorithm];
  if ($key_details['bits'] < $required_bits) {
    form_set_error('algorithm', t('Key size (%size bits) is too small for algorithm chosen. Algorithm requires a minimum of %required bits.',
      array('%size' => $key_details['bits'], '%required' => $required_bits)));
  }

  if ($key_details['type'] !== OPENSSL_KEYTYPE_RSA) {
    form_set_error('algorithm', t('Key must be RSA.'));
  }

  openssl_pkey_free($key_resource);
}
