<?php
/**
 * Attribute and Role Mapping Tab Template
 *
 * This template renders the attribute and role mapping configuration interface
 * with IDP selection, reset functionality, and tabbed navigation.
 *
 * @package MOSAML
 * @since 1.0.0
 */
// phpcs:ignoreFile WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedVariableFound -- Template scope variables.

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\SRC\Utils\Feature_Control;
use MOSAML\SRC\Utils\Utility;

if ( ! empty( $configured_idps ) ) {
	?>
	<div class="mosaml-tab-content-section mosaml-margin-top-bottom-0-2-rem">
		<table class="mosaml-table-width">
			<tbody>
				<tr></tr>
			</tbody>
		</table>
		<table class="mosaml-table-width mosaml-no-border-bottom">
			<tbody>
				<tr>
					<td>
						<b>Select your IDP</b>
					</td>
					<td class="mo-saml-idp-selector-td">
						<?php Utility::add_select_your_idp_dropdown( $configured_idps, $selected_idp_id ); ?>
					</td>
					<td>
						<span class="mosaml-float-right">
							<?php
							$reset_target = ( '0' === $selected_idp || empty( $selected_idp ) ) ? 'All IDPs' : $selected_idp;
							?>
							<input type="button" 
									class="button button-primary button-large" 
									value="Reset <?php echo esc_attr( $reset_button_name ); ?> Configurations for <?php echo esc_attr( $selected_idp_name ); ?>" 
									onclick="submitResetConfiguration('<?php echo esc_js( $active_subtab ); ?>', '<?php echo esc_js( $selected_idp_name ); ?>')"
									<?php
									echo esc_attr( Feature_Control::get_disabled_attribute( $disable_reset_button_version ) );
									echo esc_attr( $disable_due_to_no_idp );
									?>
									>
						</span>
					</td>
				</tr>
			</tbody>
		</table>
	</div>
	<form name="mosaml_reset_<?php echo esc_attr( $active_subtab ); ?>" id="mo_saml_reset_<?php echo esc_attr( $active_subtab ); ?>" method="post" action="">
		<?php wp_nonce_field( 'mosaml_reset_' . esc_attr( $active_subtab ) ); ?>
		<input type="hidden" name="option" value="mosaml_reset_<?php echo esc_attr( $active_subtab ); ?>" />
		<input type="hidden" name="selected_idp_name" value="<?php echo esc_attr( $selected_idp ); ?>" />
	</form>
	<?php
}
?>
<div class="mo-saml-nav-subtab-div">
	<a class="mo-saml-nav-subtab mosaml-text-decoration-none <?php echo( 'attribute_mapping' === $active_subtab ? 'mo-saml-nav-subtab-active' : '' ); ?>" href="<?php echo esc_url( $attribute_mapping_subtab_url ); ?>">Attribute Mapping
	</a> 
	<a class="mo-saml-nav-subtab mosaml-text-decoration-none <?php echo( 'role_mapping' === $active_subtab ? 'mo-saml-nav-subtab-active' : '' ); ?>" href="<?php echo esc_url( $role_mapping_subtab_url ); ?>">Role Mapping
	</a>
	<a class="mo-saml-nav-subtab mosaml-text-decoration-none <?php echo( 'role_mapping_advanced_settings' === $active_subtab ? 'mo-saml-nav-subtab-active' : '' ); ?>" href="<?php echo esc_url( $role_mapping_advanced_settings_subtab_url ); ?>">Advanced Settings
		<?php Feature_Control::get_feature_lock_icon( 3 ); ?>
	</a>
</div>
<?php
if ( empty( $test_config_attributes ) && 'All IDPs' != $selected_idp_name && $is_current_environment ) {
	?>
	<div class="mosaml-tabs-backgroud-color">
		<br>
		<?php Feature_Control::check_plugin_state(); ?>
		<table class="mo-saml-empty-idp-attrs-table">
			<tr>
				<td colspan="3">
					<br>
					<div>
						<div class="mo-saml-info-logo-container">
							<i class="mo-saml-info-logo-circle">i</i>
							<div>Attributes received from IDP will help you to configure <b>Attribute Mapping</b> and <b>Role Mapping</b>. To get the list of IDP attributes, please refer to the following steps:</div></br>
						</div>
						<div class="mo-saml-test-steps">
							<?php if ( is_countable( $configured_idps ) &&  $idp_count >= 1 ) : ?>
								&bull; Click on the <a href="#" onClick="showTestWindow('<?php echo esc_url( Utility::get_test_config_url( $selected_idp_id, true ) ); ?>');"><b>Test Configuration</b></a>.</br>
							<?php else : ?>
								&bull; Please configure an IDP in <a href="<?php echo esc_url( $service_provider_setup_url ); ?>"><b>IDP Configuration</b></a> Tab first.</br>
								&bull; Click on the <b>Test Configuration</b>.</br>
							<?php endif; ?>
							&bull; Once the Test Configuration is successful, you will find the list of IDP attributes on the right side of the page.
						</div>
					</div>
				</td>
			</tr>
		</table>
		<br>
	</div>
	<?php
}
