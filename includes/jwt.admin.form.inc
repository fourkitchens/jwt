<?php

/**
 * @file
 * Admin settings form for the JWT Module.
 */

/**
 * Returns a Drupal config form array.
 *
 * @param array $form
 *   Optional Drupal form array.
 * @param array $form_state
 *   Optional Drupal form state array.
 *
 * @return array
 *   The Drupal form array.
 */
function jwt_config_form(array $form = array(), array $form_state = array()) {
  $lib_info = libraries_load('php-jwt');
  if (!$lib_info['loaded']) {
    drupal_set_message(t('Unable to load the php-jwt library. Check that it is <a href="@url">properly installed</a>.', array(
      '@url' => url('https://www.drupal.org/docs/7/modules/libraries-api/installing-an-external-library-that-is-required-by-a-contributed-module'),
    )));
    return $form;
  }
  $form['key-container'] = array(
    '#type' => 'container',
    '#prefix' => '<div id="jwt-key-container">',
    '#suffix' => '</div>',
    '#weight' => 10,
  );

  $algorithm_options = JwtTranscoder::getAlgorithmOptions();
  $form['jwt_algorithm'] = array(
    '#type' => 'select',
    '#title' => t('Algorithm'),
    '#options' => $algorithm_options,
    '#ajax' => array(
      'callback' => 'jwt_config_form_key_ajax',
      'event' => 'change',
      'wrapper' => 'jwt-key-container',
      'progress' => array(
        'type' => 'throbber',
      ),
    ),
    '#default_value' => variable_get('jwt_algorithm'),
  );

  if (empty($form_state['values']['jwt_algorithm'])) {
    $jwt_algorithm = \variable_get('jwt_algorithm');
    if (!empty($jwt_algorithm)) {
      $type = JwtTranscoder::getAlgorithmType(variable_get('jwt_algorithm'));
    }
    else {
      $type = 'jwt_hs';
    }
  }
  else {
    $type = JwtTranscoder::getAlgorithmType($form_state['values']['jwt_algorithm']);
  }
  $text = ($type === 'jwt_hs') ? t('Secret') : t('Private Key');

  $form['key-container']['jwt_key_id'] = array(
    '#type' => 'key_select',
    '#title' => $text,
    '#default_value' => variable_get('jwt_key_id'),
    '#key_filters' => array(
      'type' => $type,
    ),
    '#validated' => TRUE,
    '#required' => TRUE,
  );

  $form['#validate'][] = 'jwt_config_form_validate';

  return system_settings_form($form);
}

/**
 * Returns the Drupal JWT Config form key element for an ajax call.
 *
 * @param array $form
 *   The Drupal form array.
 * @param array $form_state
 *   The Drupal form state.
 *
 * @return array
 *   The key form element.
 */
function jwt_config_form_key_ajax(array $form, array $form_state) {
  return $form['key-container'];
}

/**
 * Validates a Drupal form array submission.
 *
 * @param array $form
 *   The Drupal form build array.
 * @param array $form_state
 *   The Drupal form state array.
 */
function jwt_config_form_validate(array &$form, array $form_state) {
  $algorithm = $form_state['values']['jwt_algorithm'];
  $key_id = $form_state['values']['jwt_key_id'];
  $key = key_get_key($key_id);

  if ($key !== NULL
    && $key['key_type'] !== JwtTranscoder::getAlgorithmType($algorithm)) {
    form_set_error('jwt_key_id', t('Incorrect key type selected.'));
  }

  if ($key !== NULL && $key['key_type_settings']['algorithm'] !== $algorithm) {
    form_set_error('jwt_key_id', t('Key does not match algorithm selected.'));
  }
}
