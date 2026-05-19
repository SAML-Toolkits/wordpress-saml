<?php
/**
 * Advanced Settings form template.
 *
 * @package miniorange-saml-20-single-sign-on/template
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\SRC\Constant\Constants;
use MOSAML\SRC\Utils\Feature_Control;
use MOSAML\SRC\Utils\Utility;

?>

<div class="mo-saml-settings-container mosaml-margin-top-bottom-0-2-rem">
	<h3>Display SSO User Tag in WordPress Users List</h3>
	<hr>
	<?php Feature_Control::check_plugin_state(); ?>
	<br>
	<div class="mo-saml-settings-internal-container">
		<?php Feature_Control::start_feature_lock_container( 3 ); ?>
		<form class="mo-saml-margin-bottom-5px" id="mo_saml_sso_show_user" method="post" action="">
			<?php wp_nonce_field( 'mosaml_sso_show_user' ); ?>
			<input type="hidden" name="option" value="mosaml_sso_show_user"/>
			<label class="switch">
				<input type="checkbox" id="mo_saml_sso_show_user" name="mo_saml_sso_show_user" value="checked" <?php echo esc_attr( $sso_user_data->sso_show_user ); ?> onchange="this.form.submit();" <?php echo esc_attr( $disable_due_to_no_idp ); ?>/>
				<span class="slider round"></span>
			</label>
			<span class="mo-saml-advanced-settings-description">
				<b>Enable this option to display an SSO tag next to SSO-authenticated users in the WordPress Users list.</b>
			</span>
		</form>
		<?php Feature_Control::end_feature_lock_container( 3 ); ?>
	</div>
	<br><br>
</div>

<div class="mo-saml-settings-container mosaml-margin-top-bottom-0-2-rem">
	<h3>Enable Complete Logout</h3>
	<hr>
	<?php Feature_Control::check_plugin_state(); ?>
	<br>
	<div class="mo-saml-settings-internal-container">
		<?php Feature_Control::start_feature_lock_container( 4 ); ?>
			<?php if ( ! empty( $configured_idps ) ) { ?>
				<form id="force_logout_idp_name_form" method="post" action="">
					<input type="hidden" name="option" value="sso_button_idp_name_option" />											
					<input type="hidden" name="complete_logout_idp" id="complete_logout_idp" value="<?php echo esc_attr( $selected_idp_id ); ?>" />
					<?php wp_nonce_field( 'sso_button_idp_name_option' ); ?>
					<table>
						<tr>
							<td class="mo_saml_select_your_idp_table_width"><b>Select your IDP</b></td>
							<td>
								<?php Utility::add_select_your_idp_dropdown( $configured_idps, $selected_idp_id ); ?>
							</td>
						</tr>
					</table>
				</form>
				<br>
			<?php } ?>
			<form id="enable_complete_logout_form" method="post" action="">
				<?php wp_nonce_field( 'mosaml_enable_complete_logout_option' ); ?>
				<input type="hidden" name="option" value="mosaml_enable_complete_logout_option" />
				<input type="hidden" name="complete_logout_idp" id="complete_logout_idp" value="<?php echo esc_attr( $selected_idp ); ?>" />
				<div class="mosaml-padding-top-bottom-1-rem">
					<label class="switch">
						<input type="checkbox"
							name="saml_force_complete_logout"
							id="enable_comp_logout"
							value="checked"
							<?php
							echo checked( $saml_force_complete_logout, 'checked', false ) . ' ' .
							disabled( ! Utility::mo_saml_is_no_idps_configured(), false );
							?>
							onchange="this.form.submit();"
						/>
						<span class="slider round"></span>
					</label>
					<span class="mo-saml-5px-padding-left"><b>Enable Complete Logout</b></span>
					<a class="mo_saml_description" id="help_complete_logout_title">[What does this mean?]</a>
					<br>
					<div hidden id="help_complete_logout_desc" class="mo_saml_help_desc">
						<span>
							Enabling this ensures a complete logout from all WordPress sessions whenever an IdP-initiated SLO request is received.
							<br>
							This requires the NameID attribute to be mapped to either the username or the email address. Check your attribute mappings <a href="<?php echo esc_url( get_admin_url() . 'admin.php?page=mo_saml_settings&tab=attribute_role_mapping&idp=' . $selected_idp_id ); ?>">here</a>.
						</span>
					</div>
				</div>
			</form>
		<?php Feature_Control::end_feature_lock_container( 4 ); ?>
	</div>
	<br>
</div>

<div class="mo-saml-settings-container mosaml-margin-top-bottom-0-2-rem">
	<h3>Customize Messages Shown to Users</h3>
	<hr>
	[&nbsp;<a href="<?php echo esc_url( Constants::CUSTOM_MESSAGES_DOC_URL ); ?>" target="_blank">Click here</a> to know how this is useful. ]
	<br><br><br>
	<?php Feature_Control::check_plugin_state(); ?>
	<div class="mo-saml-settings-internal-container">
		<?php Feature_Control::start_feature_lock_container( 3 ); ?>
		<form class="mo-saml-advanced-settings-form" name="saml_form" method="post" action="">
			<?php wp_nonce_field( 'mosaml_add_custom_messages' ); ?>
			<input type="hidden" name="option" value="mosaml_add_custom_messages" />	
			<div class="mo-saml-advanced-settings-table">		
				<div class="mosaml-advance-settings-form-row">
					<div class="mosaml-advance-settings-label"><strong>User creation Disabled Message</strong></div>
					<div>
						<textarea rows="6" cols="35" name="mo_saml_account_creation_disabled_msg" placeholder="Your custom message for account creation disabled error." class="mo-saml-textarea-field mosaml-advance-settings-textarea" <?php echo esc_attr( $disable_due_to_no_idp ); ?>><?php echo esc_attr( $custom_message_data->account_creation_disabled_msg ); ?></textarea>
					</div>
				</div>
				<div class="mosaml-advance-settings-form-row">
					<div class="mosaml-advance-settings-label"><strong>Restricted Domain Error Message</strong></div>
					<div>
						<textarea rows="6" cols="35" name="mo_saml_restricted_domain_error_msg" placeholder="Your custom message for restricted domain error." class="mo-saml-textarea-field mosaml-advance-settings-textarea" <?php echo esc_attr( $disable_due_to_no_idp ); ?>><?php echo esc_attr( $custom_message_data->restricted_domain_error_msg ); ?></textarea>
					</div>
				</div>
				<div id="save_config_element" class="mosaml-advance-settings-submit-container">
					<br/>
					<input type="submit" name="submit" value="Save" class="button button-primary button-large mo-saml-submit-button-width" <?php echo esc_attr( $disable_due_to_no_idp ); ?>/>
				</div>
			</div>
		</form>
		<?php Feature_Control::end_feature_lock_container( 3 ); ?>
		<br/>
	</div>
	<br>
</div>
