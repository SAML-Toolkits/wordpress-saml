<?php
/**
 * Auto-Redirect from WordPress Login Template.
 *
 * @package miniorange-saml-20-single-sign-on
 */
// phpcs:ignoreFile WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedVariableFound -- Template scope variables.

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\SRC\Utils\Feature_Control;

?>
<div class="mo-saml-settings-container" id="mo-saml-redirect-from-wp-login-div">
	<h3>Auto Redirection from WordPress Login Page</h3>
	<hr>
	<div>
		<form id="mo_saml_enable_redirect_form" method="post" action="">
			<?php Feature_Control::start_feature_lock_container( 2 ); ?>
			<?php wp_nonce_field( 'mosaml_login_page_auto_redirection' ); ?>
			<br>
			<input type="hidden" name="option" value="mosaml_login_page_auto_redirection"/>
			<label class="switch">
				<input type="checkbox" name="mo_saml_enable_login_redirect" <?php echo esc_attr( $disable_login_page_redirect_toggle ); ?> value="checked"
				<?php echo esc_attr( $login_page_auto_redirection_data->redirect_from_wp_login ); ?>/>
				<span class="slider round"></span>
			</label>
			<span class="mo-saml-redirect-from-wp-login-label"><b>Redirect to Default IdP from WordPress Login Page</b></span>
			<a class="mo_saml_description" id="redirect_default_idp_wp">[What does this mean?]</a>
			<div hidden id="redirect_default_idp_wp_desc" class="mo_saml_help_desc">
			<span>Enable the above option if you want the users visiting any of the following URLs to get redirected to the Default IdP for authentication:</span>
			<br>
			<code><b><?php echo esc_url( $wp_login_url ); ?></b></code> or
			<code><b><?php echo esc_url( $wp_admin_url ); ?></b></code><br>
			</div>
		</form>
		<br>	
		
		
		<form id="mo_saml_allow_wp_signin_form" method="post" action="">
			<?php wp_nonce_field( 'mosaml_backdoor_url_login' ); ?>
			<input type="hidden" name="option" value="mosaml_backdoor_url_login"/>
			<p>
				<label class="switch">
					<input type="checkbox" name="mo_saml_allow_wp_signin" <?php echo esc_attr( $disabled_due_to_license ); ?> value="checked"
					<?php echo esc_attr( $backdoor_url_login_data->enable_backdoor_url_login ); ?>
					onchange="changeBackdoorLogin()" />
					<span class="slider round"></span>
				</label>
				<span class="mo-saml-redirect-from-wp-login-label"><b>Enable Backdoor Login</b></span>
				<a class="mo_saml_description" id="backdoor_url_wp">[What does this mean?]</a>
				<div hidden id="backdoor_url_wp_desc" class="mo_saml_help_desc">
				Enabling this option creates a backdoor to login to your Website using WordPress credentials in case you get locked out of your IdP.
				</div>
				<table class="mo-saml-redirect-from-wp-login-table">
					<tr>
						<td class="mo-saml-redirect-from-wp-login-td"><br><b>Backdoor URL:</b><br>(Please note it down) </td>
						<td><br>
							<div class="mo_backdoor_container">
								<div>
									<b><?php
									$backdoor_login_url = $wp_login_url;
									$backdoor_param_sep  = ( strpos( $backdoor_login_url, '?' ) !== false ) ? '&' : '?';
									echo esc_url( $backdoor_login_url . $backdoor_param_sep . 'saml_sso=' );
									?>
									<input class="mo-saml-redirect-from-wp-login-input" type="text" id="backdoor_url" name="mo_saml_backdoor_url" <?php echo esc_attr( $disabled_due_to_license ); ?> pattern="^[a-zA-Z0-9_\-]+$" required oninput="checkInputValidity(this)" 
									<?php echo esc_attr( $disable_backdoor_url_options ); ?>
									value="<?php echo esc_attr( $backdoor_url_login_data->backdoor_url ); ?>"></b>
									<i class="mo_copy backdoor_mo_copy copytooltip" onclick="copyBackdoorUrl(this, '<?php echo esc_url( $backdoor_login_url ); ?>');" pattern="^[a-zA-Z0-9_\-]+$" required oninput="checkInputValidity(this)">
									<svg viewBox="0 0 512 512" xmlns="http://www.w3.org/2000/svg" ><path d="M502.6 70.63l-61.25-61.25C435.4 3.371 427.2 0 418.7 0H255.1c-35.35 0-64 28.66-64 64l.0195 256C192 355.4 220.7 384 256 384h192c35.2 0 64-28.8 64-64V93.25C512 84.77 508.6 76.63 502.6 70.63zM464 320c0 8.836-7.164 16-16 16H255.1c-8.838 0-16-7.164-16-16L239.1 64.13c0-8.836 7.164-16 16-16h128L384 96c0 17.67 14.33 32 32 32h47.1V320zM272 448c0 8.836-7.164 16-16 16H63.1c-8.838 0-16-7.164-16-16L47.98 192.1c0-8.836 7.164-16 16-16H160V128H63.99c-35.35 0-64 28.65-64 64l.0098 256C.002 483.3 28.66 512 64 512h192c35.2 0 64-28.8 64-64v-32h-47.1L272 448z" /></svg>
										<span id="backdoor_url_copy" class="copytooltiptext">Copy to Clipboard</span>
									</i>
								</div>
								<input type="submit" value="Update" class="button button-primary" <?php echo esc_attr( $disabled_due_to_license ); ?>
								<?php echo esc_attr( $disable_backdoor_url_options ); ?>
								/>
							</div>
						</td>
					</tr>
					<tr>
						<td class="mo-saml-redirect-from-wp-login-td"></td>
						<td><div class="mo-saml-redirect-from-wp-login-note"><b>Note:</b> (Checking the above option will <b>enable a security hole</b>. Anybody knowing the above URL will be able to login to your website using WordPress Credentials. <b>Please do not share this URL</b>.)</div><br></td>
					</tr>
				</table>
				<?php Feature_Control::end_feature_lock_container( 2 ); ?>
			</p><hr>
		</form>
	</div>
	
	<div id="mo-saml-domain-mapping">
		<div>
			<h3>Domain Mapping</h3>
			<?php
			$disable_domain_mapping = '';
			?>
			<?php if ( ! Feature_Control::is_feature_locked( 4 ) && ( $login_page_auto_redirection_data->redirect_from_wp_login || ( $site_auto_redirection_data->enable_site_auto_redirect && 'public_page' === $site_auto_redirection_data->site_auto_redirection_option ) ) ) : ?>
				<?php
				$disable_domain_mapping         = 'disabled';
				$disable_domain_mapping_options = 'disabled';
				?>
				<div class="mo-saml-not-logged-in-notice">It seems you have enabled
				<?php if ( $login_page_auto_redirection_data->redirect_from_wp_login && ( $site_auto_redirection_data->enable_site_auto_redirect && 'public_page' === $site_auto_redirection_data->site_auto_redirection_option ) ) : ?>
					<b> Redirect to Default IDP from WordPress login page</b> & <b>Auto-redirect to the public page of the site</b> options
				<?php elseif ( $login_page_auto_redirection_data->redirect_from_wp_login ) : ?>
					<b> Redirect to Default IDP from WordPress login page</b> option
				<?php elseif ( $site_auto_redirection_data->enable_site_auto_redirect && 'public_page' === $site_auto_redirection_data->site_auto_redirection_option ) : ?>
					<b> Auto-redirect to the public page of the site</b> option 
				<?php endif; ?>
					from above, Please disable it if you want to use the Domain Mapping Feature.</div>
			<?php endif; ?>
			<?php Feature_Control::start_feature_lock_container( 4 ); ?>
			<form name="saml_form_domain_mapping" id="saml_form_domain_mapping" method="post" action="">
				<?php wp_nonce_field( 'mosaml_domain_mapping' ); ?>
				<input type="hidden" name="option" value="mosaml_domain_mapping"/>
				<table class="mo-saml-domain-mapping-table">
					<tr>
						<td colspan="2">
							<label class="switch">
								<input type="checkbox" id="mo_saml_enable_domain_mapping" name="mo_saml_enable_domain_mapping" value="checked" onchange="submitDomainMappingForm()" 
								<?php
								echo ( ' ' . esc_attr( $disable_domain_mapping ) );
								echo ( ' ' . esc_attr( $disable_due_to_no_idp ) );
								?>
								<?php echo esc_attr( $domain_mapping_data->enable_domain_mapping ); ?>/>
								<span class="slider round"></span>
							</label>
							<span class="mo-saml-domain-mapping-label"><b>Enable SSO Login based on Domain Mapping</b></span>
							<a href="#" id="enable_domain_mapping">[What does this mean?]</a>
							<br>
							<div hidden id="enable_domain_mapping_desc" class="mo_saml_help_desc">
								<span>Select this option if you want to enable the SSO by Domain Mapping. User will have to enter the email-id to login and if their domain is mapped then they will be redirected to that IDP otherwise they will be asked to login using WordPress credentials. If this option is disabled then you need to provide the link of each IDP to login.</span>
							</div>
						</td>
					</tr>
					<tr>
						<td colspan="3">
							<br/><b>If Domain Mapping fails (Choose One): </b>
						</td>
					</tr>
					<tr>
						<td colspan="3">
							<input class="mosaml-radio-button-margin" type="radio" name="domain_login_failed_option" value="wp_login"
							<?php echo 'wp_login' === $domain_mapping_data->domain_mapping_fail_option ? 'checked' : ''; ?>
							<?php echo ' ' . esc_attr( $disable_domain_mapping_options ); ?>/> Allow User to login via WP credentials. 
						</td>
					</tr>
					<tr>
						<td colspan="3">
							<input class="mosaml-radio-button-margin" type="radio" name="domain_login_failed_option" value="default_idp"
							<?php echo 'default_idp' === $domain_mapping_data->domain_mapping_fail_option ? 'checked' : ''; ?>
							<?php echo ' ' . esc_attr( $disable_domain_mapping_options ); ?>/> Redirect to Default Identity Provider.
						</td>
					</tr>
					<tr>
						<td><br></td>
					</tr>
					<?php
					foreach ( $configured_idps_without_default as $idp_details ) :
						?>
						<tr>
							<td class="mo-saml-domain-mapping-idp-name">
								<?php echo esc_html( $idp_details->idp_name ); ?> 
								<?php if ( $idp_details->default_idp ) : ?>
									<div class="mosaml-default-idp-div">
										<span class="mosaml-default-idp-label">
											Default
										</span>
										<a href="https://faq.miniorange.com/knowledgebase/what-is-default-identity-provider/" target="_blank" rel="noopener noreferrer" class="mosaml-no-outline-link">
											<svg class="mosaml-default-idp-icon" width="17" height="17" x="0" y="0" viewBox="0 0 24 24" xml:space="preserve">
												<g>
													<path d="M12 22C6.486 22 2 17.514 2 12S6.486 2 12 2s10 4.486 10 10-4.486 10-10 10zm0-18c-4.411 0-8 3.589-8 8s3.589 8 8 8 8-3.589 8-8-3.589-8-8-8z" fill="#3e8fd0" opacity="1" data-original="#000000"></path>
													<path d="M12 16.75a1 1 0 0 1-1-1v-4.282a1 1 0 0 1 2 0v4.282a1 1 0 0 1-1 1zM12 9.25c-.26 0-.52-.11-.71-.29-.18-.19-.29-.45-.29-.71 0-.13.03-.26.08-.38s.12-.23.21-.33c.38-.37 1.04-.37 1.42 0 .18.19.29.45.29.71s-.11.52-.29.71c-.1.09-.21.16-.33.21-.12.06-.25.08-.38.08z" fill="#3e8fd0" opacity="1" data-original="#000000"></path>
												</g>
											</svg>
										</a>
									</div>
								<?php endif; ?>
							</td>
							<td>
								<input class="mo-saml-domain-mapping-text" type="text" name="saml_domain_mapping_<?php echo esc_attr( $idp_details->idp_id ); ?>"
									placeholder="Enter semi-colon separated domains. Eg. miniorange.com"
									value="<?php echo isset( $domain_mapping_data->domain_mapping_config[ $idp_details->idp_id ] ) ? esc_attr( $domain_mapping_data->domain_mapping_config[ $idp_details->idp_id ] ) : ''; ?>"
									<?php echo ' ' . esc_attr( $disable_domain_mapping_options ); ?>
								/>
							</td>
						</tr>
					<?php endforeach; ?>
					<tr>
						<td colspan="2">
							<br/> 
							<input type="submit" class="mo-saml-domain-mapping-submit button button-primary button-large mo-saml-submit-button-width" value="Save" <?php echo esc_attr( $disable_domain_mapping_options ); ?>/>
						</td>
					</tr>
				</table>
			</form>
			<?php Feature_Control::end_feature_lock_container( 4 ); ?>
		</div>
		<br>
	</div>
</div>
</br> 
