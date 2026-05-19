<?php
/**
 * Redirection After SSO Template.
 *
 * @package miniorange-saml-20-single-sign-on
 */
// phpcs:ignoreFile WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedVariableFound -- Template scope variables.

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\SRC\Utils\Feature_Control;
use MOSAML\SRC\Utils\Utility;

?>
<div class="mo-saml-settings-container" id="mo-saml-redirection-after-sso-div">
	<h3>Redirection after SSO Settings</h3>
	<hr>
	<table id="mo_relay_state">
		<tr>
			<td class="mo_saml_select_your_idp_table_width"><b>Select your IDP</b></td>
			<td>
				<?php Utility::add_select_your_idp_dropdown( $identity_providers, $idp_id ); ?>
			</td>
		</tr>
		<tr>
			<td></td>
			<td>
				<b>NOTE:</b> If <i> specific Relay States </i> for IDPs are saved, they will be used. If not, default Relay States for all IDPs will be used for any IDP without a specified Relay State.
			</td>
		</tr>
	</table>
	<br>
	<form id="mosaml_relay_state" method="post" action="
		<?php
			$request_uri = isset( $_SERVER['REQUEST_URI'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : '';
		?>
		">
		<?php wp_nonce_field( 'mosaml_relay_state' ); ?>
		<input type="hidden" name="option" value="mosaml_relay_state">
		<input type="hidden" name="mo_saml_relay_state_idp_name" value="<?php echo esc_attr( $id ); ?>">
		<table>
			<tr>
				<td colspan="2">
					<div class="mosaml-lock-wrapper">
						<?php Feature_Control::show_tooltip_for_disabled_feature( 3 ); ?>
						<label class="switch">
							<input type="checkbox" name="mo_saml_allow_3rd_party_url" value="checked" <?php echo esc_attr( $disable_due_to_no_idp ); ?> <?php echo esc_attr( Feature_Control::get_disabled_attribute( 3 ) ); ?> <?php echo esc_attr( $relay_state_data->allow_third_party_relay_state ); ?>/>
							<span class="slider round"></span>
						</label>
						<span class="mo-saml-sso-button-label"><b>Allow 3rd Party URLs in Relay States</b></span>						
					</div>
					<br>
				</td>
			</tr>
		</table>
		<?php Feature_Control::start_feature_lock_container( 2 ); ?>
		<table>
			<tr>
				<td class="mo_saml_select_your_idp_table_width"><b>Login Relay State URL:</b></td>
				<td>
					<input type="url" name="mo_saml_login_relay_state" class="mo-saml-redirection-after-sso-input" <?php echo esc_attr( $disable_due_to_no_idp ); ?> placeholder="Enter a valid URL (Example: <?php echo esc_url_raw( $sp_base_url ); ?>)" value="<?php echo esc_url_raw( isset( $relay_state_data->login_relay_state ) ? $relay_state_data->login_relay_state : '' ); ?>" 
					>
				</td>
			</tr>
			<tr>
				<td></td>
				<td>Users will always be redirected to this URL after SSO.<br/>When left blank, the users will be redirected to the same page from where the SSO was initiated.</td>
			</tr>
			<tr>
				<td colspan="2"><br/></td>
			</tr>
		</table>
		<?php Feature_Control::end_feature_lock_container( 2 ); ?>
		<?php echo( Feature_Control::is_feature_locked( 2 ) ? '<br>' : '' ); ?>
		<?php Feature_Control::start_feature_lock_container( 3 ); ?>
		<table>
			<tr>
				<td class="mo_saml_select_your_idp_table_width"><b>Logout Relay State URL:</b></td>
				<td>
					<input type="url" name="mo_saml_logout_relay_state" class="mo-saml-redirection-after-sso-input" <?php echo esc_attr( $disable_due_to_no_idp ); ?> placeholder="Enter a valid URL (Example: <?php echo esc_url_raw( $sp_base_url ); ?>)" value="<?php echo esc_url_raw( isset( $relay_state_data->logout_relay_state ) ? $relay_state_data->logout_relay_state : '' ); ?>">
				</td>
			</tr>
			<tr>
				<td></td>
				<td>SSO Users will always be redirected to this URL after Logout.<br/>When left blank, the SSO users will be redirected to the same page from where the Logout was initiated.</td>
			</tr>
		</table>
		<?php Feature_Control::end_feature_lock_container( 3 ); ?>
		<div class="mo-saml-redirection-after-sso-center">
			<input type="submit" <?php echo esc_attr( $disable_due_to_no_idp ); ?> value="Save" class="button button-primary button-large mo-saml-submit-button-width" <?php echo esc_attr( Feature_Control::get_disabled_attribute( 2 ) ); ?>>
		</div>
	</form>
	<br>
</div>
