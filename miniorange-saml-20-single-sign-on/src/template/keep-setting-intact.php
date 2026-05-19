<?php
/**
 * Keep Settings Intact template.
 *
 * @package miniorange-saml-20-single-sign-on/template
 */
// phpcs:ignoreFile WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedVariableFound -- Template scope variables.

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\SRC\Utils\Feature_Control;
use MOSAML\SRC\Utils\Utility;

?>
<div class="mosaml-tab-content-section mosaml-margin-top-bottom-0-2-rem" id="mo_saml_keep_configuration_intact">
	<h3>Plugin Configurations</h3>
	<hr>
	<br/>
	<form method="post" action="" id="settings_intact">
		<?php wp_nonce_field( 'mosaml_keep_settings_on_deletion' ); ?>
		<input type="hidden" name="option" value="mosaml_keep_settings_on_deletion"/>
		<label class="switch">
			<input type="checkbox" name="mo_saml_keep_settings_intact" value="checked" <?php echo esc_attr( $keep_settings_intact ); ?>
				onchange="document.getElementById('settings_intact').submit();" />
			<span class="slider round"></span>
		</label>
		<span class="mosaml-checkbox-label mo-saml-heading" ><b>Keep Settings Intact</b></span>
		<br/><br/>
		Enabling this would keep your configurations intact even when the plugin is uninstalled.
	</form>
	<br/><br />
	<?php
		$form_action = add_query_arg(
			array(
				'page' => 'mo_saml_settings',
				'tab'  => ! empty( $current_tab ) ? $current_tab : 'sp_setup',
			),
			admin_url( 'admin.php' )
		);
	?>
	<form method="post" id="import_config" action="<?php echo esc_url( $form_action ); ?>" enctype="multipart/form-data">
		<?php wp_nonce_field( 'mosaml_import' ); ?>
		<input type="hidden" name="option" value="mosaml_import" />
		<table class="mo_saml_settings-table">
			<tr>
				<td><span class="mo-saml-heading" ><b>Import Configurations</b></span></td>
			</tr>
			<tr>
				<td><br/></td>
			</tr>
			<tr>
				<td>
					<input type="file" name="configuration_file" id="configuration_file" <?php echo esc_attr( $disabled_due_to_license ); ?>>
				</td>
				<td>
					<input type="submit" name="submit" class="button button-primary button-large" value="Import" <?php echo esc_attr( $disabled_due_to_license ); ?> />
				</td>
			</tr>
		</table>
	</form>
</div>
