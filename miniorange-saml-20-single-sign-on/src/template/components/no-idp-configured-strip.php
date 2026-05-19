<?php
/**
 * This file contains the HTML code for the strip shown when no idp is configured.
 *
 * @package MOSAML
 * @subpackage MOSAML/src/template
 */
// phpcs:ignoreFile WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedVariableFound -- Template scope variables.

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

$request_uri = isset( $_SERVER['REQUEST_URI'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : '';
?>

<div class="mosaml-license-strip">
	Please configure an IDP in <a href="<?php echo esc_url( add_query_arg( array( 'tab' => 'sp_setup' ), $request_uri ) ); ?>">IDP Configuration</a> tab to access these features.
</div>
