<?php
/**
 * Salesforce notice template.
 * 
 * @package miniorange-saml-20-single-sign-on
 */

use MOSAML\SRC\Constant\Constants;

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}
?>
<div class="mo-saml-advertise-notice-body">
	<img src="<?php echo esc_url( plugins_url( Constants::PLUGIN_NAME . '/static/image/idp-logos/salesforce.webp' ) ); ?>" class="mo-saml-advertise-notice-logo" alt="" />
	<div class="mo-saml-advertise-notice-wrap">
		<div class="mo-saml-txt-container">
			<b>Looks like you're making the most of Salesforce's Platform.</b>
		</div>
		<div class="mo-saml-img-container">
			<span>Explore our additional integration:</span>
			<a href="https://plugins.miniorange.com/wordpress-object-sync-for-salesforce" target="_blank" rel="noopener noreferrer" class="mo-saml-text-decoration mo-saml-img-container">
				<img src="<?php echo esc_url( plugins_url( Constants::PLUGIN_NAME . '/static/image/idp-logos/salesforce.webp' ) ); ?>" width="24" height="24" alt="" />Object Data Sync For Salesforce
			</a>
		</div>
	</div>
</div>
