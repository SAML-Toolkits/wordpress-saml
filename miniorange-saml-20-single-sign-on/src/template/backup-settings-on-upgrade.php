<?php
/**
 * Backup Settings on Upgrade template.
 *
 * @package miniorange-saml-20-single-sign-on/template
 */
// phpcs:ignoreFile WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedVariableFound -- Template scope variables.

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\SRC\Constant\Constants;

$enable_plugin_backup_on_upgrade = get_option( Constants::ENABLE_BACKUP_SETTINGS, 'checked' );

?>
<div class="mosaml-tab-content-section mosaml-margin-top-bottom-0-2-rem" id="mo_saml_keep_configuration_intact">
	<h3><?php esc_html_e( 'Create Plugin Backup on Upgrade', 'miniorange-saml-20-single-sign-on' ); ?></h3>
	<hr>
	<br/>
	<form method="post" action="" id="mo_saml_enable_plugin_backup_on_upgrade">
		<?php wp_nonce_field( 'mosaml_enable_plugin_backup_on_upgrade' ); ?>
		<input type="hidden" name="option" value="mosaml_enable_plugin_backup_on_upgrade" />
		<label class="switch">
			<input type="checkbox" id="mo_saml_enable_backup_settings" name="mo_saml_enable_backup_settings" value="checked" <?php checked( $enable_plugin_backup_on_upgrade, 'checked' ); ?>
				onchange="document.getElementById('mo_saml_enable_plugin_backup_on_upgrade').submit();" />
			<span class="slider round"></span>
		</label>
		<span class="mosaml-checkbox-label mo-saml-heading" ><b><?php esc_html_e( 'Enable Plugin Backup', 'miniorange-saml-20-single-sign-on' ); ?></b></span>
		<br/><br/>
		<?php esc_html_e( 'Enable this option to automatically create a backup of the plugin before upgrading to a new version. The backup will be stored in your WordPress uploads directory.', 'miniorange-saml-20-single-sign-on' ); ?>
	</form>
</div>
