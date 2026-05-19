<?php
/**
 * This file contains the HTML code for the strip shown when license verification is required.
 *
 * @package MOSAML
 * @subpackage MOSAML/src/template/components
 */
// phpcs:ignoreFile WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedVariableFound -- Template scope variables.

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

$request_uri = isset( $_SERVER['REQUEST_URI'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : '';
?>

<div class="mosaml-license-strip">
	Please enter your <a href="<?php echo esc_url( add_query_arg( array( 'tab' => 'account_settings' ), $request_uri ) ); ?>">license key</a> to activate the plugin.
</div>
