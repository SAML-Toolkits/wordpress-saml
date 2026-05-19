<?php
/**
 * Certificate expired security alert notice.
 *
 * Shown at the top of the plugin admin page when the SP certificate has expired.
 *
 * @package miniorange-saml-20-single-sign-on/template/components
 */
// phpcs:ignoreFile WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedVariableFound -- Template scope variables.

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

$certificate_upgrade_url = add_query_arg(
	array(
		'page' => 'mo_saml_settings',
		'tab'  => 'custom_certificate',
	),
	admin_url( 'admin.php' )
);
?>

<div class="mosaml-certificate-expired-security-alert" role="alert">
	<strong><?php esc_html_e( 'Security Alert', 'miniorange-saml-20-single-sign-on' ); ?>:</strong>
	<?php
	echo wp_kses_post(
		sprintf(
			/* translators: 1: opening anchor tag for upgrade link, 2: closing anchor tag */
			__( 'Your certificate has expired, please upgrade your certificate immediately. %1$sUpgrade your certificate%2$s or your SSO will stop.', 'miniorange-saml-20-single-sign-on' ),
			'<a href="' . esc_url( $certificate_upgrade_url ) . '" class="mosaml-certificate-expired-alert-link">',
			'</a>'
		)
	);
	?>
</div>
