<?php
/**
 * This file contains the HTML code for the strip shown when login is required.
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
	Please <a href="<?php echo esc_url( add_query_arg( array( 'page' => 'mo_saml_settings' ), admin_url( 'admin.php' ) ) ); ?>">Register or Login with miniOrange</a> to configure the miniOrange SAML Plugin.
</div>
