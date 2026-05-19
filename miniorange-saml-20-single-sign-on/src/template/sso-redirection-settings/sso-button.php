<?php
/**
 * SSO Button Template.
 *
 * @package miniorange-saml-20-single-sign-on
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\SRC\Utils\Feature_Control;
use MOSAML\SRC\Constant\Plugin_Files_Constants;

?>

<div class="mo-saml-settings-container" id="mo-saml-login-button">
	<h3 class="mo-saml-sso-button-header">
		<b>Add SSO Login Button on WP Login Page</b>
		<span class="mo-saml-sso-button-reset-button">
			<input type="button" onClick="resetConfigurationPrompt('mo_saml_reset_sso_button_form','Are you sure you want to reset all the SSO Login Button settings? This action will reset the button configuration for <?php echo esc_attr( $idp_name ); ?>.')" class="button button-primary button-large" 
			value="Reset Login Button Settings" <?php echo esc_attr( isset( $disable_due_to_no_idp ) ? $disable_due_to_no_idp : '' ); ?> <?php echo esc_attr( Feature_Control::get_disabled_attribute( 3 ) ); ?>>
		</span>
	</h3>
	<hr>
	<form id="mo_saml_reset_sso_button_form" method="post" action="">
		<?php wp_nonce_field( 'mosaml_reset_sso_button_option' ); ?>
		<input type="hidden" name="option" value="mosaml_reset_sso_button_option">
		<input type="hidden" name="sso_link_idp" value="<?php echo esc_attr( $id ); ?>">
	</form>
	<?php require_once Plugin_Files_Constants::TEMPLATE_SSO_BUTTON_SUBSECTION; ?>
</div>
<br>
