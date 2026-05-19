<?php
/**
 * Login Page SSO Button Template.
 *
 * @package miniorange-saml-20-single-sign-on
 */
// phpcs:ignoreFile WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedVariableFound -- Template scope variables.

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

?>

<input id="saml_user_login_input_<?php echo esc_attr( $idp_id ); ?>" type="hidden" name="option" value="">
<input id="saml_idp_id_<?php echo esc_attr( $idp_id ); ?>" type="hidden" name="idp_id" value="<?php echo esc_attr( $idp_id ); ?>">
<?php if ( ! empty( $button_styles_css ) ) : ?>
	<style type="text/css"><?php echo $button_styles_css; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped ?></style>
<?php endif; ?>

<div
	id="mo_saml_button_<?php echo esc_attr( $idp_id ); ?>"
	name="mo_saml_button"
	class="mo-saml-login-button-container"
	data-position="<?php echo esc_attr( $position ); ?>"
	data-idp-id="<?php echo esc_attr( $idp_id ); ?>"
	data-sso-base="<?php echo esc_url( $sp_base_url ); ?>"
>
	<?php if ( $is_below && ( 'checked' !== $hide_wp_login_object->hide_wp_login || $is_backdoor_login ) ) : ?>
		<div class="mo-saml-or-separator"><b><?php esc_html_e( 'OR', 'miniorange-saml-20-single-sign-on' ); ?></b></div>
	<?php endif; ?>
	<div id="mo_saml_login_sso_button_<?php echo esc_attr( $idp_id ); ?>" class="mo-saml-login-sso-button <?php echo esc_attr( $class_name ); ?>">
		<?php $allowed_tags = array(
				'div'    => array(
					'id'    => array(),
					'style' => array(),
					'name'  => array(),
				),
				'a'      => array(
					'href'  => array(),
					'style' => array(),
				),
				'img'    => array(
					'style' => array(),
					'src'   => array(),
				),
				'script' => array(
					'type' => array(),
				),
				'b'      => array(),
			);
		echo wp_kses( $button_html, $allowed_tags ); ?>
	</div>
	<?php if ( ! $is_below && ( 'checked' !== $hide_wp_login_object->hide_wp_login || $is_backdoor_login ) ) : ?>
		<div class="mo-saml-or-separator"><b><?php esc_html_e( 'OR', 'miniorange-saml-20-single-sign-on' ); ?></b></div>
	<?php endif; ?>
</div> 
