<?php
/**
 * Database update admin notice template.
 *
 * @package miniorange-saml-20-single-sign-on
 */
// phpcs:ignoreFile WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedVariableFound -- Template scope variables.

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\SRC\Constant\Constants;
use MOSAML\SRC\Utils\DB_Utils;
use MOSAML\SRC\Utils\Utility;

if ( ( DB_Utils::all_tables_exist() && 'completed' === get_option( Constants::DATABASE_UPDATE_STATUS ) ) || get_option( Constants::DISMISSED_DATABASE_UPDATE_REQUIRED_NOTICE_OPTION_NAME ) ) {
	return;
}

$button_text = 'Plugin Settings';
if ( DB_Utils::all_tables_exist() && 'completed' !== get_option( Constants::DATABASE_UPDATE_STATUS ) ) {
	$button_text = 'Setup Database';
}

$current_page = Utility::sanitize_get_data( 'page' );

$plugin_url = add_query_arg(
	array(
		'page' => 'mo_saml_settings',
	),
	admin_url( 'admin.php' )
);

?>
<div class="notice notice-error">
	<div style="display: flex; padding-top: 1rem;">
		<img style="width: 6.4rem; height: 6.4rem;" src="<?php echo esc_url( plugin_dir_url( MOSAML_PLUGIN_FILE ) . 'static/image/miniorange-logo.png' ); ?>" alt="miniOrange logo">
		<div style="padding-left: 1rem;">
			<h1>Database Update Required</h1>
			<b>Please update your database to the latest version to continue using the <a href="<?php echo esc_url( $plugin_url ); ?>">miniOrange SAML SSO</a> plugin.</b>
			<p style="color: red; font-style: italic;">
				Note: Your <b>SSO functionality will continue to work</b> without any issues during this process.
			</p>
		</div>
	</div>
	<br>
	<?php if ( 'mo_saml_settings' !== $current_page ) : ?>
		<?php if ( 'Plugin Settings' === $button_text ) : ?>
			<button class="button button-primary button-large" onclick="window.location.href='<?php echo esc_url( $plugin_url ); ?>';"><?php echo esc_html( $button_text ); ?></button>&nbsp;&nbsp;
		<?php else : ?>
			<button class="button button-primary button-large" onclick="submitFormById('mosaml_setup_database_form');"><?php echo esc_html( $button_text ); ?></button>&nbsp;&nbsp;
		<?php endif; ?>
		<button class="button button-secondary button-large" onclick="submitFormById('mosaml_dismiss_database_update_required_form');">Dismiss</button>
		<br><br>
	<?php endif; ?>
	<form id="mosaml_setup_database_form" method="post" action="<?php echo esc_url( $plugin_url ); ?>">
		<?php wp_nonce_field( 'mosaml_setup_database' ); ?>
		<input type="hidden" name="option" value="mosaml_setup_database">
	</form>
	<form id="mosaml_dismiss_database_update_required_form" method="post" action="">
		<?php wp_nonce_field( 'mosaml_dismiss_database_update_required' ); ?>
		<input type="hidden" name="option" value="mosaml_dismiss_database_update_required">
	</form>
</div>
<script>
	function submitFormById(formId) {
		const form = document.getElementById(formId);
		if (form) {
			form.submit();
		}
	}
</script>
