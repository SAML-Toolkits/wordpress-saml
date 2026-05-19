<?php
/**
 * SSO Links Template.
 *
 * @package miniorange-saml-20-single-sign-on
 */
// phpcs:ignoreFile WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedVariableFound -- Template scope variables.

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\SRC\Utils\Utility;
use MOSAML\SRC\Utils\DB_Utils;

if ( $is_enterprise && ! empty( $identity_providers ) ) {
	?>
	<div class="mo_saml_attribute_role_table mo-saml-attribute-role-table-margin">
		<table width="98%">
			<tr>
				<td class="mo-saml-idp-select-width"><strong>Select your IDP</strong></td>
				<td>
				<?php Utility::add_select_your_idp_dropdown( $identity_providers, $idp_id ); ?>
				</td>
			</tr>
		</table>
	</div>
	<br>
	<?php
}
?>

<div class="mo-saml-settings-container" id="mo-saml-sso-link">
	<h3>SSO Links</h3>
	<hr>
	<?php
		$selected_environment_id = DB_Utils::get_environment_details( 'id', false );
		if( Utility::mo_saml_is_no_idps_configured( $selected_environment_id ) ) {
			?>
			<b>No IDP Configured. Please configure an IDP to get the SSO Links.</b>
			</br>
			</br>
			<?php
		} else {
			?>
			<table class="mo-saml-sso-links-table">
				<tr>
					<td>
						<b>
							Use the following link to add on your HTML Pages for users to initiate SSO from the site:
						</b>
					</td>
				</tr>
				<tr><td><br></td></tr>
				<tr class="mo-saml-sso-links-flex-row">
					<td class="mo-saml-sso-links-margin-top">
						<b>SSO URL for <?php echo esc_attr( $idp_name ); ?></b>
					</td>
					<td></td>
				</tr>
				<tr>
					<td>
						<div class="mo-saml-sso-links-flex-container">
							<a id="sso_url_link" class="mo_saml_sso_link_url_layout" href="<?php echo esc_url( $sp_base_url ) . '/?option=saml_user_login&idp=' . esc_attr( $idp_id ); ?>">
								<?php echo esc_url( $sp_base_url ) . '/?option=saml_user_login&idp=' . esc_attr( $idp_id ); ?>
							</a>
							<i class="mo_copy copytooltip mo-saml-copy-icon-no-float" onclick="copyToClipboard(this, '#sso_url_link', '#copytooltiptext');">
								<svg viewBox="0 0 512 512" xmlns="http://www.w3.org/2000/svg">
									<path d="M502.6 70.63l-61.25-61.25C435.4 3.371 427.2 0 418.7 0H255.1c-35.35 0-64 28.66-64 64l.0195 256C192 355.4 220.7 384 256 384h192c35.2 0 64-28.8 64-64V93.25C512 84.77 508.6 76.63 502.6 70.63zM464 320c0 8.836-7.164 16-16 16H255.1c-8.838 0-16-7.164-16-16L239.1 64.13c0-8.836 7.164-16 16-16h128L384 96c0 17.67 14.33 32 32 32h47.1V320zM272 448c0 8.836-7.164 16-16 16H63.1c-8.838 0-16-7.164-16-16L47.98 192.1c0-8.836 7.164-16 16-16H160V128H63.99c-35.35 0-64 28.65-64 64l.0098 256C.002 483.3 28.66 512 64 512h192c35.2 0 64-28.8 64-64v-32h-47.1L272 448z" />
								</svg>
								<span id="copytooltiptext" class="copytooltiptext">Copy to Clipboard</span>
							</i>
						</div>
					</td>
					<td></td>
				</tr>
				<tr></tr>
				<tr>
					<td>
						<br>
						<b>Note:</b>
						If you want to redirect the user to a Page after the authentication, then use the SSO Link as given below :
					</td>
					<td></td>
				</tr>
				<tr></tr>
				<tr class="mo-saml-sso-links-flex-row">
					<td>
						<div class="mo-saml-sso-links-flex-container">
							<a id="sso_url_link_redirect" class="mo_saml_sso_link_redct_text" href="<?php echo esc_url( $sp_base_url ) . '/?option=saml_user_login&idp=' . esc_attr( $idp_id ) . '&redirect_to=page_url'; ?>">
								<?php echo esc_url( $sp_base_url ) . '/?option=saml_user_login&idp=' . esc_attr( $idp_id ) . '&redirect_to='; ?><span class="mo-saml-red-text">page_url</span>
							</a>
							<i class="mo_copy copytooltip mo-saml-copy-icon-no-float" onclick="copyToClipboard(this, '#sso_url_link_redirect', '#copytooltip_rdct_text');">
								<svg viewBox="0 0 512 512" xmlns="http://www.w3.org/2000/svg">
									<path d="M502.6 70.63l-61.25-61.25C435.4 3.371 427.2 0 418.7 0H255.1c-35.35 0-64 28.66-64 64l.0195 256C192 355.4 220.7 384 256 384h192c35.2 0 64-28.8 64-64V93.25C512 84.77 508.6 76.63 502.6 70.63zM464 320c0 8.836-7.164 16-16 16H255.1c-8.838 0-16-7.164-16-16L239.1 64.13c0-8.836 7.164-16 16-16h128L384 96c0 17.67 14.33 32 32 32h47.1V320zM272 448c0 8.836-7.164 16-16 16H63.1c-8.838 0-16-7.164-16-16L47.98 192.1c0-8.836 7.164-16 16-16H160V128H63.99c-35.35 0-64 28.65-64 64l.0098 256C.002 483.3 28.66 512 64 512h192c35.2 0 64-28.8 64-64v-32h-47.1L272 448z" />
								</svg>
								<span id="copytooltip_rdct_text" class="copytooltiptext">Copy to Clipboard</span>
							</i>
						</div>
					</td>
					<td></td>
				</tr>
				<tr></tr>
				<tr>
					<td>
						<b>Replace the <span class="mo-saml-red-text">page_url</span> with the url of the Page.</b>
					</td>
					<td></td>
				</tr>
				<tr></tr>
			</table>
			<?php
		}
	?>
</div>

<br/>
