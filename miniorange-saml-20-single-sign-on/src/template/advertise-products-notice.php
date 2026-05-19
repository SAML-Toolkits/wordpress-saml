<?php
/**
 * Advertise products notice template.
 *
 * @package miniorange-saml-20-single-sign-on
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

?>

<div class="mo-saml-display-notice">
	<div class="mo-saml-market-notice-container">
		<?php echo $notice_content; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Notice content is built by the plugin. ?>
		<form method="POST" action="<?php echo esc_url( admin_url( 'admin-ajax.php' ) ); ?>" class="mo-saml-advertise-notice-close-form">
			<input type="hidden" name="action" value="mo_saml_close_advertise_products_notice">
			<input type="hidden" name="notice_type" value="<?php echo esc_attr( isset( $notice_type ) ? $notice_type : '' ); ?>">
			<button type="submit" class="button" aria-label="<?php esc_attr_e( 'Dismiss notice', 'miniorange-saml-20-single-sign-on' ); ?>">
				<svg viewBox="0 0 20 20" xmlns="http://www.w3.org/2000/svg" fill="currentColor" width="18" height="18" class="mo-saml-dismiss-notice" aria-hidden="true">
					<path d="M10 2c4.42 0 8 3.58 8 8s-3.58 8-8 8-8-3.58-8-8 3.58-8 8-8zm5 11l-3-3 3-3-2-2-3 3-3-3-2 2 3 3-3 3 2 2 3-3 3 3z"></path>
				</svg>
			</button>
			<?php wp_nonce_field( 'mo_saml_close_advertise_products_notice' ); ?>
		</form>
	</div>
</div>