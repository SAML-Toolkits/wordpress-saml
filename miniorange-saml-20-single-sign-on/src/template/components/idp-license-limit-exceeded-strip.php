<?php
/**
 * This file contains the HTML code for the strip shown
 * when the configured IDPs exceed the licensed IDP limit.
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
	You have configured more Identity Providers than your license allows.
	Please review your <a href="<?php echo esc_url( add_query_arg( array( 'tab' => 'account_settings' ), $request_uri ) ); ?>" style="color:#b30000;text-decoration:underline;">license details</a>
	or remove extra IDP configurations.
</div>

