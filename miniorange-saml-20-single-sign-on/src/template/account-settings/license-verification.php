<?php
/**
 * License Verification form template.
 *
 * @package miniorange-saml-20-single-sign-on/template
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\SRC\Constant\URL_Constants;

?>
<div class="mosaml-tab-content-section mosaml-margin-top-bottom-0-2-rem">
	<h3 class="mo-saml-license-title">Verify License
		<span class="mo-saml-license-link">
			[ <a href="<?php echo esc_url( URL_Constants::PORTAL_VIEW_LICENSE_URL ); ?>" target="_blank" class="mo-saml-license-view-link">Click here to view your license key</a> ]
		</span>
	</h3>
	<hr class="mo-saml-license-hr">
	<form name="f" method="post" action="">
	<?php wp_nonce_field( 'mosaml_verify_license', '_wpnonce' ); ?>
		<input type="hidden" name="option" value="mosaml_verify_license">

		<div class="mo-saml-sso-links-table mo-saml-license-input-group mo-saml-license-flex-row">
			<label for="mo_saml_license_key" class="mo-saml-license-label mo-saml-font-bold mo-saml-license-label-inline">
				Enter your license key to activate the plugin <span class="mo-saml-required-asterisk">*</span>
			</label>
			<input 
				class="mo-saml-width-350 mosaml-radio-post mo-saml-license-input" 
				required 
				type="text" 
				id="mo_saml_license_key"
				name="mo_saml_license_key" 
				placeholder="Enter your license key"
				style="margin-left: 29px;"
			>
		</div>

		<div class="mo-saml-license-checkbox-group">
			<label class="mo-saml-license-label mo-saml-font-bold">
				Please check this to confirm that you have read it <span class="mo-saml-required-asterisk">*</span>
			</label>
			<input style="margin-left: 10px;" required type="checkbox" name="license_conditions" class="mo-saml-license-checkbox">
		</div>

		<ol class="mo-saml-license-info-list">
			<li>
				The license key you enter here is associated with this site instance. If you reinstall the plugin or your site, please deactivate and delete the plugin from the WordPress console (do not manually delete the plugin folder) to reuse the same license key.
			</li>
			<li class="mo-saml-license-info-list-item">
				<b>This is not a developer's license.</b> Any changes to the plugin's code will delete all your configuration and make the plugin unusable.
			</li>
		</ol>

		<div class="mo-saml-license-btn-group">
			<input type="submit" name="submit" value="Activate License" class="button button-primary button-large">
			<input type="button" class="button button-secondary button-large" value="Back" onclick="document.forms['mo_saml_back_license'].submit();">
		</div>
	</form>
	<form name="f" method="post" action="" id="mo_saml_back_license">
		<?php wp_nonce_field( 'mosaml_back_license_verification' ); ?>
		<input type="hidden" name="option" value="mosaml_back_license_verification"/>
	</form>
</div>
