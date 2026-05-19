<?php
/**
 * Azure notice template.
 *
 * @package miniorange-saml-20-single-sign-on
 */

use MOSAML\SRC\Constant\Constants;

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}
?>
<div class="mo-saml-advertise-notice-body">
	<img src="<?php echo esc_url( plugins_url( Constants::PLUGIN_NAME . '/static/image/idp-logos/azure-ad.webp' ) ); ?>" class="mo-saml-advertise-notice-logo" alt="" />
	<div class="mo-saml-advertise-notice-wrap">
		<div class="mo-saml-txt-container">
			<b>Looks like you're making the most of Microsoft's suite.</b>
		</div>
		<div class="mo-saml-img-container">
			<span>Discover more of our integrations:</span>
			<a href="https://plugins.miniorange.com/microsoft-power-bi-embed-for-wordpress" target="_blank" rel="noopener noreferrer" class="mo-saml-text-decoration mo-saml-img-container">
				<img src="<?php echo esc_url( plugins_url( Constants::PLUGIN_NAME . '/static/image/power-bi-logo.webp' ) ); ?>" width="22" height="22" alt="" />Power BI,
			</a>
			<a href="https://plugins.miniorange.com/microsoft-sharepoint-wordpress-integration" target="_blank" rel="noopener noreferrer" class="mo-saml-text-decoration mo-saml-img-container">
				<img src="<?php echo esc_url( plugins_url( Constants::PLUGIN_NAME . '/static/image/sharepoint-logo.webp' ) ); ?>" width="20" height="20" alt="" />SharePoint Document Library,
			</a>
			<a href="https://plugins.miniorange.com/wp-user-sync-for-azure-office365" target="_blank" rel="noopener noreferrer" class="mo-saml-text-decoration mo-saml-img-container">
				<img src="<?php echo esc_url( plugins_url( Constants::PLUGIN_NAME . '/static/image/Bussiness-directory-logo.webp' ) ); ?>" width="18" height="18" alt="" />Business Directory.
			</a>
		</div>
	</div>
</div>