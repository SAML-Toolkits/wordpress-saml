<?php
/**
 * Missing PHP extensions notice template.
 * Shown when required extensions (OpenSSL, DOM, cURL) are not loaded.
 *
 * @package miniorange-saml-20-single-sign-on
 */
// phpcs:ignoreFile WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedVariableFound -- Template scope variables.

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

if ( empty( $missing_extensions ) || ! is_array( $missing_extensions ) ) {
	return;
}

$extensions_list = implode( ', ', array_map( 'esc_html', $missing_extensions ) );
?>
<div class="wrap">
	<h1><?php esc_html_e( 'miniOrange SAML SSO', 'miniorange-saml-20-single-sign-on' ); ?></h1>
	<div class="mosaml-tab-content-section mosaml-margin-top-bottom-0-2-rem">
		<div class="notice notice-error">
			<h2><?php esc_html_e( 'Required PHP extensions missing or disabled', 'miniorange-saml-20-single-sign-on' ); ?></h2>
			<p>
				<?php
				echo esc_html__(
					'The following PHP extension(s) are required to use this plugin but are not installed or are disabled:',
					'miniorange-saml-20-single-sign-on'
				);
				?>
				<strong> <?php echo $extensions_list; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Already escaped above. ?></strong>
			</p>
			<p>
				<?php esc_html_e( 'Please enable them in your php.ini file and restart the web server.', 'miniorange-saml-20-single-sign-on' ); ?>
			</p>
			<p>
				<?php esc_html_e( 'Example (uncomment the relevant lines in php.ini):', 'miniorange-saml-20-single-sign-on' ); ?>
			</p>
			<ul style="list-style: disc; margin-left: 2em;">
				<li><code>extension=openssl</code></li>
				<li><code>extension=curl</code></li>
				<li><code>extension=dom</code></li>
			</ul>
			<p>
				<?php esc_html_e( 'On WAMP/XAMPP, use the tray icon to open php.ini, then restart Apache.', 'miniorange-saml-20-single-sign-on' ); ?>
			</p>
		</div>
	</div>
</div>
