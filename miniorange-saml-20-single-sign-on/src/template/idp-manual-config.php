<?php
/**
 * IDP Manual Configuration Template
 *
 * @package miniorange-saml-20-single-sign-on
 */
// phpcs:ignoreFile WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedVariableFound -- Template scope variables.

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\SRC\Constant\Constants;
use MOSAML\SRC\Utils\Feature_Control;

?>
<div class="mosaml-tab-content-section mosaml-margin-top-bottom-0-2-rem">
	<div class="mosaml-div-flex-row mosaml-div-flex-row-space-between">
		<?php if ( 'edit' === $action ) : ?>
			<h3 class="mosaml-section-heading">Edit Identity Provider Configuration</h3>
		<?php else : ?>
			<h3 class="mosaml-section-heading">Add New IDP</h3>
		<?php endif; ?>
		<div class="mosaml-button-container">
			<a href="<?php echo esc_url( $upload_metadata_url ); ?>">
				<input type="button" class="button button-primary button-large" <?php echo esc_attr( $disabled_due_to_license ); ?> value="Upload IDP Metadata" />
			</a>
			<a href="<?php echo esc_url( $cancel_url ); ?>">
				<input type="button" value="Cancel" class="button button-primary button-large" <?php echo esc_attr( $disabled_due_to_license ); ?> />
			</a>
		</div>
	</div>
	<hr>
	<form name="saml_form" method="post" action="<?php echo esc_url( $action_url ); ?>">
		<?php wp_nonce_field( 'mosaml_login_widget_saml_save_settings' ); ?>
		<input type="hidden" name="option" value="mosaml_login_widget_saml_save_settings" />
		<input type="hidden" name="upload_metadata" value="manual" />
		<input type="hidden" name="mosaml_edit_idp_name" value="<?php echo 'edit' !== $action ? esc_attr( $data->idp_name ) : esc_attr( $data->idp_id ); ?>" />
		
		<?php if ( ! empty( $metadata_sync_data ) && ! empty( $metadata_sync_data->sync_metadata ) ) : ?>
			<div style="display:block;width:95%;box-sizing:border-box;margin-top:10px;margin-bottom:10px;color:red;background-color:rgba(251, 232, 0, 0.15);padding:5px;border:solid 1px rgba(255, 0, 9, 0.36);">
				Please Note that the <b><a href="#metadata-sync">Metadata Sync</a> is enabled,</b> and hence the
				<?php if ( ! empty( $metadata_sync_data->sync_only_certificate ) && 'checked' === $metadata_sync_data->sync_only_certificate ) : ?>
					<b>X.509 Certificate Value(s)<?php else : ?><b>manual config<?php endif; ?>
				 would be overridden</b> by configurations recieved at every sync.
			</div>
		<?php endif; ?>

		<table class="mosaml-table-width">
			<tr id="mo_saml_selected_idp_div" class="mosaml-selected-idp-row">
				<td><strong>Identity Provider:</strong></td>
				<td>
					<div class="mosaml-selected-idp-container" id="selected_idp_div">
						<div id="mo_saml_selected_idp_icon_div" class="mosaml-selected-idp-icon">
						</div>
						<a target="_blank" class="button button-primary mosaml-guide-link" id="saml_idp_guide_link" href="">Click here to open Guide</a>
						<a target="_blank" class="button button-primary mosaml-video-link" id="saml_idp_video_link">Click here to view Setup Video</a>
						<input type="hidden" id="saml_identity_provider_guide_name" name="mosaml_identity_provider_guide_name" value="<?php echo esc_attr( $data->idp_name ); ?>" />
					</div>
					<br>
				</td>
			</tr>
			<tr id="custom_idp_selected" hidden>
				<td colspan="3">
					<p class="mosaml-custom-idp-note">
						Note: Please feel free to reach out to us in case of any issues for setting up the Custom IDP using the Contact Us dialog.
					</p>
				</td>
			</tr>
			<tr>
				<td class="mosaml-label-cell">
					<strong>Identity Provider Name <span class="mosaml-required">*</span>:</strong>
				</td>
				<td>
					<input type="text" 
							name="saml_identity_name" 
							placeholder="Identity Provider name like ADFS, SimpleSAML, Salesforce" 
							class="mosaml-input-field" 
							value="<?php echo esc_attr( $data->idp_name ); ?>" 
							required 
							pattern="^(?=.*[a-zA-Z0-9])[a-zA-Z0-9\s_\-@]+$" 
							title="Special characters are not allowed except underscore(_), hyphen(-) and @." />
				</td>
			</tr>
			
			<tr>
				<td>&nbsp;</td>
			</tr>
			
			<tr>
				<td class="mosaml-label-cell">
					<strong>SP Entity ID <span class="mosaml-required">*</span>:</strong>
				</td>
				<td>
					<?php Feature_Control::start_feature_lock_container( 4 ); ?>
					<input type="text" 
							name="saml_sp_entity_id"
							placeholder="Service Provider Entity ID"
							class="mosaml-input-field" 
							value="<?php echo esc_attr( $data->sp_entity_id ); ?>" 
							required 
							pattern="^[^\s]+$" 
							title="SP Entity ID should not contain spaces. Please remove any spaces and try again." />
					<?php Feature_Control::end_feature_lock_container( 4 ); ?>
				</td>
			</tr>
			
			<tr>
				<td>&nbsp;</td>
			</tr>
			
			<tr>
				<td class="mosaml-label-cell">
					<strong>IDP Entity ID or Issuer <span class="mosaml-required">*</span>:</strong>
				</td>
				<td>
					<input type="text" 
							name="saml_issuer"
							placeholder="Identity Provider Entity ID or Issuer"
							class="mosaml-input-field" 
							value="<?php echo esc_attr( $data->entity_id ); ?>" 
							required 
							pattern="^[^\s]+$" 
							title="Identity Provider Entity ID or Issuer should not contain spaces. Please remove any spaces and try again." />
				</td>
			</tr>
			
			<tr>
				<td>&nbsp;</td>
			</tr>
			
			<tr>
				<td><strong>Sign SSO & SLO Requests:</strong></td>
				<td>
					<?php Feature_Control::start_feature_lock_container( 2 ); ?>
					<label class="switch">
						<input type="checkbox" name="saml_request_signed" value="checked" <?php echo esc_attr( $data->sign_sso_slo_request ); ?> />
						<span class="slider round"></span>
					</label>
					<span class="mosaml-checkbox-label"><b>Check this option to send Signed SSO and SLO requests</b></span>
					<?php Feature_Control::end_feature_lock_container( 2 ); ?>
				</td>
			</tr>
			
			<tr>
				<td>&nbsp;</td>
			</tr>
			
			<tr>
				<td class="mosaml-label-cell">
					<strong>SAML Login URL <span class="mosaml-required">*</span>:</strong>
				</td>
				<td>
					<input type="radio" 
							name="saml_login_binding_type" 
							id="sso-http-redirect" 
							value="HttpRedirect" 
							<?php echo ( 'HttpRedirect' === $data->sso_binding || empty( $data->sso_binding ) ) ? 'checked="checked"' : ''; ?> <?php echo esc_attr( Feature_Control::get_disabled_attribute( 2 ) ); ?> />
					<label for="sso-http-redirect">Use HTTP-Redirect Binding for SSO</label>
					
					<input type="radio" 
							name="saml_login_binding_type" 
							id="sso-http-post" 
							value="HttpPost" 
							class="mosaml-radio-post"
							<?php echo ( 'HttpPost' === $data->sso_binding ) ? 'checked="checked"' : ''; ?> <?php echo esc_attr( Feature_Control::get_disabled_attribute( 2 ) ); ?> />
					<label for="http-post">Use HTTP-POST Binding for SSO</label>
					<br><br>
					<input type="url" 
							name="saml_login_url" 
							placeholder="Single Sign On Service URL of your IdP" 
							class="mosaml-input-field" 
							value="<?php echo esc_url( $data->sso_url ? $data->sso_url : '' ); ?>" 
							required 
							pattern="^[^\s]+$" 
							title="SAML Login URL should not contain spaces. Please remove any spaces and try again." />
				</td>
			</tr>
			
			<tr>
				<td>&nbsp;</td>
			</tr>
			
			<tr>
				<td><strong>SAML Logout URL :</strong></td>
				<td>
					<?php Feature_Control::start_feature_lock_container( 3 ); ?>
					<input type="radio" 
							name="saml_logout_binding_type" 
							id="slo-http-redirect" 
							value="HttpRedirect" 
							<?php echo ( 'HttpRedirect' === $data->slo_binding || empty( $data->slo_binding ) ) ? 'checked="checked"' : ''; ?> />
					<label for="slo-http-redirect">Use HTTP-Redirect Binding for SLO</label>
					
					<input type="radio" 
							name="saml_logout_binding_type" 
							id="slo-http-post" 
							value="HttpPost" 
							class="mosaml-radio-post"
							<?php echo ( 'HttpPost' === $data->slo_binding ) ? 'checked="checked"' : ''; ?> />
					<label for="slo-http-post">Use HTTP-POST Binding for SLO</label>
					<br><br>
					<input type="url" 
							name="saml_logout_url" 
							placeholder="Single Logout Service URL of your IdP" 
							class="mosaml-input-field" 
							value="<?php echo esc_url( $data->slo_url ? $data->slo_url : '' ); ?>" 
							pattern="^[^\s]+$" 
							title="SAML Logout URL should not contain spaces. Please remove any spaces and try again." />
					<?php Feature_Control::end_feature_lock_container( 3 ); ?>
					<br><br>
				</td>
			</tr>
			
			<tr id="saml_pw_reset_url_row" hidden>
				<td><strong>Password Reset Link :</strong></td>
				<td>
					<?php Feature_Control::start_feature_lock_container( 4 ); ?>
					<input type="text"
						id="saml_password_reset_url"
						name="saml_password_reset_url"
						placeholder="Password Reset URL for your Azure B2C tenant"
						class="mosaml-input-field"
						value="<?php echo esc_url( $data->password_reset_url ? $data->password_reset_url : '' ); ?>"
						pattern="^[^\s]+$"
						title="Password Reset URL should not contain spaces. Please remove any spaces and try again." />
					<?php Feature_Control::end_feature_lock_container( 4 ); ?>
				</td>
			</tr>
			<tr id="saml_pw_reset_url_space_below" hidden>
				<td>&nbsp;</td>
			</tr>
			
			<tr id="saml_logout_response_url_row" hidden>
				<td><strong>SAML Logout Response URL :</strong></td>
				<td>
					<?php Feature_Control::start_feature_lock_container( 3 ); ?>
					<input type="url"
						id="saml_logout_response_url"
						name="saml_logout_response_url"
						placeholder="Single Logout Response Service URL of your IdP"
						class="mosaml-input-field"
						value="<?php echo esc_url( $data->slo_response_url ? $data->slo_response_url : '' ); ?>" />
					<?php Feature_Control::end_feature_lock_container( 3 ); ?>
				</td>
			</tr>
			<tr id="saml_logout_response_url_space_below" hidden>
				<td>&nbsp;</td>
			</tr>
			
			<tr>
				<td class="mosaml-label-cell">
					<strong>NameID Format <span class="mosaml-required">*</span>:</strong>
				</td>
				<td>
					<select class="mosaml-select-field" name="saml_nameid_format" required>
						<?php foreach ( Constants::NAMEID_FORMATS as $key => $value ) : ?>
							<option value="<?php echo esc_attr( $value ); ?>" <?php echo ( $data->name_id_format === $value ) ? 'selected' : ''; ?>><?php echo esc_html( $value ); ?></option>
						<?php endforeach; ?>
					</select>
				</td>
			</tr>
			
			<tr>
				<td></td>
			</tr>
			
			<?php
			if ( empty( $data->idp_certificate ) ) :
				?>
				<tr>
					<td class="mosaml-label-cell">
						<strong>Identity Provider X.509 Certificate <span class="mosaml-required">*</span>:</strong>
					</td>
					<td>
						<textarea rows="6" 
									cols="5" 
									name="saml_x509_certificate[0]" 
									placeholder="Copy and Paste the content from the downloaded certificate or copy the content enclosed in X509Certificate tag (has parent tag KeyDescriptor use=signing) in IdP-Metadata XML file" 
									required
									class="mosaml-textarea-field"></textarea>
					</td>
				</tr>
				<tr>
					<td>&nbsp;</td>
					<td>
						<div class="mosaml-certificate-note">
							<b>NOTE:</b> Format of the certificate:<br/>
							<b>-----BEGIN CERTIFICATE-----<br/>XXXXXXXXXXXXXXXXXXXXXXXXXXX<br/>-----END CERTIFICATE-----</b>
						</div>
					</td>
				</tr>
				<?php
			else :
				$certificates = maybe_unserialize( $data->idp_certificate );

				// Handle both string and array formats.
				if ( is_string( $certificates ) ) {
					$certificates = array( $certificates );
				}

				if ( is_string( $certificates ) && ( strpos( $certificates, 's:' ) === 0 || strpos( $certificates, 'a:' ) === 0 ) ) {
					$certificates = maybe_unserialize( $certificates );
					if ( is_string( $certificates ) ) {
						$certificates = array( $certificates );
					}
				}

				if ( is_array( $certificates ) ) :
					foreach ( $certificates as $key => $value ) :
						if ( is_string( $value ) && ( strpos( $value, 's:' ) === 0 || strpos( $value, 'a:' ) === 0 ) ) {
							$unserialized_value = maybe_unserialize( $value );
							if ( is_array( $unserialized_value ) && ! empty( $unserialized_value ) ) {
								$value = $unserialized_value[0];
							} elseif ( is_string( $unserialized_value ) ) {
								$value = $unserialized_value;
							}
						}
						?>
						<tr>
							<td class="mosaml-label-cell">
								<strong>Identity Provider X.509 Certificate<span class="mosaml-required">*</span>:</strong>
							</td>
							<td>
								<textarea rows="6" 
											cols="5" 
											name="saml_x509_certificate[<?php echo esc_attr( $key ); ?>]" 
											placeholder="Copy and Paste the content from the downloaded certificate or copy the content enclosed in X509Certificate tag (has parent tag KeyDescriptor use=signing) in IdP-Metadata XML file" 
											class="mosaml-textarea-field" 
											required><?php echo esc_textarea( $value ); ?></textarea>
							</td>
						</tr>
						<tr>
							<td>&nbsp;</td>
							<td>
								<div class="mosaml-certificate-note">
									<b>NOTE:</b> Format of the certificate:<br/>
									<b>-----BEGIN CERTIFICATE-----<br/>XXXXXXXXXXXXXXXXXXXXXXXXXXX<br/>-----END CERTIFICATE-----</b>
								</div>
							</td>
						</tr>
						<?php
					endforeach;
				endif;
			endif;
			?>
			
			<tr>
				<td>&nbsp;</td>
			</tr>
			
			<tr>
				<td><strong><label for="enable_iconv">Character encoding :</label></strong></td>
				<td>
					<label class="switch">
						<input type="checkbox" name="enable_iconv" id="enable_iconv" value="checked" <?php echo esc_attr( $data->character_encoding ); ?> />
						<span class="slider round"></span>
					</label>
				</td>
			</tr>
			
			<tr>
				<td>&nbsp;</td>
				<td>
					<div class="mosaml-note">
						<b>NOTE: </b>Uses iconv encoding to convert X509 certificate into correct encoding.
					</div>
				</td>
			</tr>
			
			<tr>
				<td>&nbsp;</td>
			</tr>
			
			<tr>
				<td><strong><label for="time_check">Assertion Time Validity :</label></strong></td>
				<td>
					<label class="switch">
						<input type="checkbox" name="mo_saml_assertion_time_validity" id="time_check" value="checked" <?php echo esc_attr( $data->assertion_time_validity ); ?> />
						<span class="slider round"></span>
					</label>
				</td>
			</tr>
			
			<tr>
				<td>&nbsp;</td>
				<td>
					<div class="mosaml-note">
						<b>NOTE: </b>Disable this toggle to disable the check of time validity for SAML assertion.
					</div>
				</td>
			</tr>
			
			<tr>
				<td>&nbsp;</td>
			</tr>
			
			<tr>
				<td>&nbsp;</td>
				<td>
					<div class="mosaml-div-flex">
						<input type="submit" name="submit" value="Save" class="button button-primary button-large mosaml-manual-config-save-button" <?php echo esc_attr( $disabled_due_to_license ); ?> />
						<input type="button" name="cancel" value="Cancel" class="button button-primary button-large mo-saml-cancel-button" <?php echo esc_attr( $disabled_due_to_license ); ?> onclick="window.location.href='<?php echo esc_url( $cancel_url ); ?>'" />
					</div>
					<div class="mosaml-margin-top-0-5rem" id="mosaml_test_configuration_button_div">
						<?php
						if ( ! isset( $is_test_config_enabled ) ) {
							$is_test_config_enabled = false;
						}
						$test_config_disabled = ( 'edit' !== $action || empty( $is_test_config_enabled ) || ! $is_current_environment ) ? 'disabled' : '';
						$test_config_onclick = ( 'edit' !== $action || empty( $is_test_config_enabled ) || ! $is_current_environment ) ? '' : 'testIdpConfiguration("' . esc_url( $test_url ) . '");';
						?>
						<input type="button" name="test_config" value="Test Configuration" class="button button-primary button-large mo-saml-test-configuration-button" <?php echo esc_attr( $test_config_disabled ); ?> onclick="<?php echo esc_js( $test_config_onclick ); ?>" />
					</div>
				</td>
			</tr>
			<tr>
				<td>&nbsp;</td>
			</tr>
			<?php if ( ! empty( $end_user_test_url ) && $is_current_environment ) : ?>
			<tr>
				<td><strong><label for="time_check">End User Test Configuration Link :</label></strong></td>
				<td>
					<div style="display: flex; align-items: center; gap: 5px;">
						<a id="test_config_url" class="mo_saml_sso_link_url_layout" href="<?php echo esc_url( $end_user_test_url ); ?>"><?php echo esc_url( $end_user_test_url ); ?></a>
						<i class="mo_copy copytooltip" onclick="copyToClipboard(this, '#test_config_url', '#test_config_url_copy');">
							<svg viewBox="0 0 512 512" xmlns="http://www.w3.org/2000/svg">
								<path d="M502.6 70.63l-61.25-61.25C435.4 3.371 427.2 0 418.7 0H255.1c-35.35 0-64 28.66-64 64l.0195 256C192 355.4 220.7 384 256 384h192c35.2 0 64-28.8 64-64V93.25C512 84.77 508.6 76.63 502.6 70.63zM464 320c0 8.836-7.164 16-16 16H255.1c-8.838 0-16-7.164-16-16L239.1 64.13c0-8.836 7.164-16 16-16h128L384 96c0 17.67 14.33 32 32 32h47.1V320zM272 448c0 8.836-7.164 16-16 16H63.1c-8.838 0-16-7.164-16-16L47.98 192.1c0-8.836 7.164-16 16-16H160V128H63.99c-35.35 0-64 28.65-64 64l.0098 256C.002 483.3 28.66 512 64 512h192c35.2 0 64-28.8 64-64v-32h-47.1L272 448z" />
							</svg>
							<span id="test_config_url_copy" class="copytooltiptext">Copy to Clipboard</span>
						</i>
					</div>
				</td>
			</tr>
			<?php endif; ?>
		</table>
		<br />
	</form>
</div>
