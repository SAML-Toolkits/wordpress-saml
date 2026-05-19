<?php
/**
 * Login Button HTML Template.
 *
 * @package miniorange-saml-20-single-sign-on
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

?>
<div style="width:fit-content;">
	<a href="<?php echo esc_url( $sp_base_url . '/?option=saml_user_login&idp=' . $idp_id ); ?>" 
	style="text-decoration:none;display:flex;flex-direction:row;align-items:center;justify-content:center;">
		<div name="mo_saml_wp_sso_button" style="<?php echo esc_attr( $button_styles_css ); ?>">
			<?php echo esc_html( $button_text ); ?>
		</div>
	</a>
</div>
