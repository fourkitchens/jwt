<?php

/**
 * @file
 * Plugin definition for the JWT HMAC key type.
 */

$plugin = array(
  'label' => t('JWT HMAC Key'),
  'description' => t('A key type used for JWT HMAC algorithms.'),
  'group' => 'encryption',
  'key value' => array(
    'plugin' => 'text_field',
  ),
  'default configuration' => 'jwt_key_type_hs_defaults',
  'build configuration form' => 'jwt_key_type_hs_form',
  'generate key value' => 'jwt_key_type_hs_generate',
  'validate key value' => 'jwt_key_type_hs_validate',
);

/**
 * Returns the default configuration for JWT HMAC.
 *
 * @return array
 *   The default form configuration.
 */
function jwt_key_type_hs_defaults() {
  return array(
    'algorithm' => 'HS256',
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
function jwt_key_type_hs_form(array $form, array &$form_state) {
  $config = $form_state['storage']['key_config'] + jwt_key_type_hs_defaults();
  $algorithm_options = array(
    'HS256' => t('HMAC using SHA-256 (HS256)'),
    'HS384' => t('HMAC using SHA-384 (HS384)'),
    'HS512' => t('HMAC using SHA-512 (HS512)'),
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
function jwt_key_type_hs_get_algorithm_key_size() {
  return array(
    'HS256' => 512,
    'HS384' => 1024,
    'HS512' => 1024,
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
function jwt_key_type_hs_generate(array $config) {
  $algorithm_keysize = jwt_key_type_hs_get_algorithm_key_size();

  $algorithm = $config['algorithm'];

  if (!empty($algorithm) && isset($algorithm_keysize[$algorithm])) {
    $bytes = $algorithm_keysize[$algorithm] / 8;
  }
  else {
    $bytes = $algorithm_keysize['HS256'] / 8;
  }
  return drupal_random_bytes($bytes);
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
function jwt_key_type_hs_validate(array $form, array &$form_state, $key_value) {
  if (!$form_state['values']['algorithm']) {
    return;
  }
  // Validate the key size.
  $algorithm = $form_state['values']['algorithm'];
  $bytes = jwt_key_type_hs_get_algorithm_key_size()[$algorithm] / 8;
  if (strlen($key_value) < $bytes) {
    \form_set_error('algorithm', t('Key size (%size bits) is too small for algorithm chosen. Algorithm requires a minimum of %required bits.',
      array('%size' => strlen($key_value) * 8, '%required' => $bytes * 8)));
  }
}
