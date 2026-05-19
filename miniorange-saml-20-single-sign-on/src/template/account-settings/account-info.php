<?php
/**
 * Account Info form template.
 *
 * @package miniorange-saml-20-single-sign-on/template
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\SRC\Constant\URL_Constants;

?>
<div class="mosaml-tab-content-section mosaml-margin-top-bottom-0-2-rem">
	<div class="mo-saml-license-sync-loader-container" id="mo-saml-license-sync-loader">
		<div class="mo-saml-license-sync-loader"></div>
	</div>
	<section>
		<div style="display: flex; justify-content: space-between; align-items: center;">
			<h3>Account Details</h3>
			<div>
				<a href="<?php echo esc_url( URL_Constants::PORTAL_VIEW_LICENSE_URL ); ?>" target="_blank" class="mosaml-text-decoration-none">
					<input type="button" name="view_license_btn" class="button button-primary button-large" value="View Your License Keys" <?php echo esc_html( $license_valid_attr ); ?>>
				</a>
				<input type="button" name="mo_saml_remove_account" id="mo_saml_remove_account" class="button button-large mo-saml-remove-license" value="Remove Account" <?php echo esc_html( $license_valid_attr ); ?> onclick="mo_saml_free_up_license_key()">
			</div>
		</div>
		<hr>
		<div class="mo_saml_profile_section">
			<div class="mo_saml_profile_box">
				<div>
					<svg width="100" height="100" version="1.1" viewBox="0 0 100 100">
							<image width="100" height="100" xlink:href="data:image/png;base64,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"/>
						</svg>
				</div>
				<div class="mo_saml_profile_box_custid">
					<span class="mo_saml_text_black">Customer ID</span> : <?php echo esc_html( $customer_id ); ?>
				</div>
			</div>
			<div class="mo_saml_profile_box_desc">
				<p><span class="mo_saml_text_black">Email</span> : <?php echo esc_html( $customer_email ); ?> </p>
				<p><span class="mo_saml_text_black">License Expiry</span> :
					<span id="mo_saml_license_expiry"> <?php echo esc_html( $expiry_date ); ?> </span>
				</p>
				<p><span class="mo_saml_text_black">IDPs Allowed</span> :
					<?php echo esc_html( (string) $allowed_idp_count ); ?>
				</p>
				<input type="button" name="ok_btn" class="button button-primary button-large mo_saml_sync_license" id="mo_saml_sync_license" value="Sync Your License" <?php echo esc_html( $license_valid_attr ); ?> onclick="confirmlicenseform()" />
				<p style="margin:5px 0 0">
					<span class="mo_saml_text_black">[ Last Synced On : </span>
					<span class="mo_saml_text_black" id = "mo_saml_last_synced">
						<?php echo esc_html( $vl_check_t ); ?>
					</span>
					<span class="mo_saml_text_black">]</span>
				</p>
			</div>
		</div>
		</br>
	<?php if ( $remaining_days <= 60 && $customer_email && $customer_id ) : ?>
		<div id="mo_saml_profile_box_expiry_notice" class="question mo_saml_profile_box_expiry_notice <?php echo esc_attr( $expiry_notice_class ); ?>">
			<img src="<?php echo esc_url( plugin_dir_url( MOSAML_PLUGIN_FILE ) . '/static/image/warning_logo.webp' ); ?>" width="3%">
			<p id="mo_saml_profile_box_license_expiry_notice <?php echo esc_attr( $expiry_notice_class ); ?>">
				<?php
				echo wp_kses(
					$box_expiry_heading,
					array(
						'span' => array(
							'id' => array(),
						),
					)
				);
				?>
			</p>
		</div>
		<div class="mo_saml_license_warning <?php echo esc_attr( $expiry_notice_class ); ?>">
			<div id="mo_saml_warning_answer" class="mo_saml_warning_answer" style="display:none;">
				<?php echo wp_kses_post( $escaped_notice_html ); ?>
			</div>
		</div>
	<?php endif; ?>

	<div class="mo_saml_faq_div">
		Here are some FAQs to clarify your doubts
	</div>

	<a href="<?php echo esc_url( $renewal_faq_url ); ?>" target="_blank">
		<div class="mo_saml_renew_faq">
			<summary style="display: flex;justify-content: space-between;">
				<div>How can I renew my license ?</div>
				<div>
					<i>
						<svg width="15px" height="15px" viewBox="0 0 24 24" version="1.1">
							<title>external_link_line</title>
							<g stroke="none" stroke-width="1" fill="none" fill-rule="evenodd">
								<g id="File" transform="translate(-480.000000, -192.000000)" fill-rule="nonzero">
									<g id="external_link_line" transform="translate(480.000000, 192.000000)">
										<path
											d="M24,0 L24,24 L0,24 L0,0 L24,0 Z M12.5934901,23.257841 L12.5819402,23.2595131 L12.5108777,23.2950439 L12.4918791,23.2987469 L12.4918791,23.2987469 L12.4767152,23.2950439 L12.4056548,23.2595131 C12.3958229,23.2563662 12.3870493,23.2590235 12.3821421,23.2649074 L12.3780323,23.275831 L12.360941,23.7031097 L12.3658947,23.7234994 L12.3769048,23.7357139 L12.4804777,23.8096931 L12.4953491,23.8136134 L12.4953491,23.8136134 L12.5071152,23.8096931 L12.6106902,23.7357139 L12.6232938,23.7196733 L12.6232938,23.7196733 L12.6266527,23.7031097 L12.609561,23.275831 C12.6075724,23.2657013 12.6010112,23.2592993 12.5934901,23.257841 L12.5934901,23.257841 Z M12.8583906,23.1452862 L12.8445485,23.1473072 L12.6598443,23.2396597 L12.6498822,23.2499052 L12.6498822,23.2499052 L12.6471943,23.2611114 L12.6650943,23.6906389 L12.6699349,23.7034178 L12.6699349,23.7034178 L12.678386,23.7104931 L12.8793402,23.8032389 C12.8914285,23.8068999 12.9022333,23.8029875 12.9078286,23.7952264 L12.9118235,23.7811639 L12.8776777,23.1665331 C12.8752882,23.1545897 12.8674102,23.1470016 12.8583906,23.1452862 L12.8583906,23.1452862 Z M12.1430473,23.1473072 C12.1332178,23.1423925 12.1221763,23.1452606 12.1156365,23.1525954 L12.1099173,23.1665331 L12.0757714,23.7811639 C12.0751323,23.7926639 12.0828099,23.8018602 12.0926481,23.8045676 L12.108256,23.8032389 L12.3092106,23.7104931 L12.3186497,23.7024347 L12.3186497,23.7024347 L12.3225043,23.6906389 L12.340401,23.2611114 L12.337245,23.2485176 L12.337245,23.2485176 L12.3277531,23.2396597 L12.1430473,23.1473072 Z"
											id="MingCute" fill-rule="nonzero"
										>
										</path>
										<path
											d="M11,6 C11.5523,6 12,6.44772 12,7 C12,7.55228 11.5523,8 11,8 L5,8 L5,19 L16,19 L16,13 C16,12.4477 16.4477,12 17,12 C17.5523,12 18,12.4477 18,13 L18,19 C18,20.1046 17.1046,21 16,21 L5,21 C3.89543,21 3,20.1046 3,19 L3,8 C3,6.89543 3.89543,6 5,6 L11,6 Z M20,3 C20.5523,3 21,3.44772 21,4 L21,4 L21,9 C21,9.55228 20.5523,10 20,10 C19.4477,10 19,9.55228 19,9 L19,9 L19,6.41421 L10.7071,14.7071 C10.3166,15.0976 9.68342,15.0976 9.29289,14.7071 C8.90237,14.3166 8.90237,13.6834 9.29289,13.2929 L9.29289,13.2929 L17.5858,5 L15,5 C14.4477,5 14,4.55229 14,4 C14,3.44772 14.4477,3 15,3 L15,3 Z"
											fill="#09244B"
										>
										</path>
									</g>
								</g>
							</g>
						</svg>
					</i>
				</div>
			</summary>
		</div>
	</a>
	<details>
		<summary>How can I free up my license Key from the current domain?</summary>
		<div class="mo_saml_faq_content">
			<p class="mo_saml_faq_answer"><span style="cursor:pointer;color:blue;" onclick="mo_saml_free_up_license_key()"> Click here </span> to free up your license key. This action will log you out from the plugin and disable SSO on your site.</p>
		</div>
	</details>
	<details>
		<summary>When is my license getting expired ?</summary>
		<div class="mo_saml_faq_content">
			<p class="mo_saml_faq_answer"><?php echo esc_html( $license_faq_answer ); ?> <b class="mo_saml_text_black"><?php echo esc_html( $expiry_date ); ?></b></p>
		</div>
	</details>
	<details>
		<summary>What happens If I do not renew my license ?</summary>
		<div class="mo_saml_faq_content">
			<p class="mo_saml_faq_answer">If you decide to cancel or not renew your license, <b style="color:red">your plugin will stop working</b>.</p>
		</div>
	</details>
	<details>
		<summary>I have paid for renewal but it is showing license expired ?</summary>
		<div class="mo_saml_faq_content">
			<p class="mo_saml_faq_answer">Click on the <button onclick="confirmlicenseform()" class="button button-primary mo-saml-faq-pointer-cursor">Sync Your License</button> button. This should sync your license details with the plugin. In case this doesn't work, please reach out to us at <a href="mailto:samlsupport@xecurify.com">samlsupport@xecurify.com</a></p>
		</div>
	</details>
	<p>
		<b><a href="<?php echo esc_url( $generic_faq_url ); ?>" target="_blank">
			Click here for more FAQs 
			<i>
				<svg width="15px" height="15px" viewBox="0 0 24 24" version="1.1">
					<title>external_link_line</title>
					<g stroke="none" stroke-width="1" fill="none" fill-rule="evenodd">
						<g id="File" transform="translate(-480.000000, -192.000000)" fill-rule="nonzero">
							<g id="external_link_line" transform="translate(480.000000, 192.000000)">
								<path
									d="M24,0 L24,24 L0,24 L0,0 L24,0 Z M12.5934901,23.257841 L12.5819402,23.2595131 L12.5108777,23.2950439 L12.4918791,23.2987469 L12.4918791,23.2987469 L12.4767152,23.2950439 L12.4056548,23.2595131 C12.3958229,23.2563662 12.3870493,23.2590235 12.3821421,23.2649074 L12.3780323,23.275831 L12.360941,23.7031097 L12.3658947,23.7234994 L12.3769048,23.7357139 L12.4804777,23.8096931 L12.4953491,23.8136134 L12.4953491,23.8136134 L12.5071152,23.8096931 L12.6106902,23.7357139 L12.6232938,23.7196733 L12.6232938,23.7196733 L12.6266527,23.7031097 L12.609561,23.275831 C12.6075724,23.2657013 12.6010112,23.2592993 12.5934901,23.257841 L12.5934901,23.257841 Z M12.8583906,23.1452862 L12.8445485,23.1473072 L12.6598443,23.2396597 L12.6498822,23.2499052 L12.6498822,23.2499052 L12.6471943,23.2611114 L12.6650943,23.6906389 L12.6699349,23.7034178 L12.6699349,23.7034178 L12.678386,23.7104931 L12.8793402,23.8032389 C12.8914285,23.8068999 12.9022333,23.8029875 12.9078286,23.7952264 L12.9118235,23.7811639 L12.8776777,23.1665331 C12.8752882,23.1545897 12.8674102,23.1470016 12.8583906,23.1452862 L12.8583906,23.1452862 Z M12.1430473,23.1473072 C12.1332178,23.1423925 12.1221763,23.1452606 12.1156365,23.1525954 L12.1099173,23.1665331 L12.0757714,23.7811639 C12.0751323,23.7926639 12.0828099,23.8018602 12.0926481,23.8045676 L12.108256,23.8032389 L12.3092106,23.7104931 L12.3186497,23.7024347 L12.3186497,23.7024347 L12.3225043,23.6906389 L12.340401,23.2611114 L12.337245,23.2485176 L12.337245,23.2485176 L12.3277531,23.2396597 L12.1430473,23.1473072 Z"
									id="MingCute" fill-rule="nonzero"
								>
								</path>
								<path
									d="M11,6 C11.5523,6 12,6.44772 12,7 C12,7.55228 11.5523,8 11,8 L5,8 L5,19 L16,19 L16,13 C16,12.4477 16.4477,12 17,12 C17.5523,12 18,12.4477 18,13 L18,19 C18,20.1046 17.1046,21 16,21 L5,21 C3.89543,21 3,20.1046 3,19 L3,8 C3,6.89543 3.89543,6 5,6 L11,6 Z M20,3 C20.5523,3 21,3.44772 21,4 L21,4 L21,9 C21,9.55228 20.5523,10 20,10 C19.4477,10 19,9.55228 19,9 L19,9 L19,6.41421 L10.7071,14.7071 C10.3166,15.0976 9.68342,15.0976 9.29289,14.7071 C8.90237,14.3166 8.90237,13.6834 9.29289,13.2929 L9.29289,13.2929 L17.5858,5 L15,5 C14.4477,5 14,4.55229 14,4 C14,3.44772 14.4477,3 15,3 L15,3 Z"
									fill="#09244B"
								>
								</path>
							</g>
						</g>
					</g>
				</svg>
			</i>
		</a></b>
	</p>
	</section>

	<form name="f" method="post" action="" id="mo_saml_remove_account_form">
		<?php wp_nonce_field( 'mosaml_remove_account' ); ?>
		<input type="hidden" name="option" value="mosaml_remove_account"/>
	</form>
	<form name="f" method="post" action="" id="mo_saml_sync_license_form">
		<?php wp_nonce_field( 'mosaml_sync_license' ); ?>
		<input type="hidden" name="option" value="mosaml_sync_license"/>
	</form>
</div>
