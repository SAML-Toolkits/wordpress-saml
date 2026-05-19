<?php
/**
 * This file contains the HTML code for the strip shown when license is expired.
 *
 * @package MOSAML
 * @subpackage MOSAML/src/template/components
 */
// phpcs:ignoreFile WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedVariableFound -- Template scope variables.

use MOSAML\LicenseLibrary\Classes\Mo_License_Constants;
use MOSAML\LicenseLibrary\Classes\Mo_License_Dao;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

$request_uri = isset( $_SERVER['REQUEST_URI'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : '';

$license_not_associated = class_exists( Mo_License_Constants::class )
	&& class_exists( Mo_License_Dao::class )
	&& Mo_License_Dao::mo_get_option( Mo_License_Constants::LICENSE_NOT_ASSOCIATED_WITH_CUSTOMER_OPTION );

$strip_message = $license_not_associated
	? 'License is not associated with this account. Hence all the plugin settings have been disabled.'
	: 'Your plugin license has expired. Hence all the plugin settings have been disabled.';
?>

<div class="mosaml-license-strip">
	<?php echo esc_html( $strip_message ); ?>
</div>
