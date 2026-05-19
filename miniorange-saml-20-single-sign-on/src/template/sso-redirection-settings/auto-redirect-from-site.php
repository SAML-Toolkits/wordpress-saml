<?php
/**
 * Auto Redirect from Site Template.
 *
 * @package miniorange-saml-20-single-sign-on
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\SRC\Utils\Feature_Control;

?>

<div class="mo-saml-settings-container" id="mo-saml-redirect-from-site-outer-div">
	<h3>Auto Redirection from Site</h3>
	<hr>
	<div id="mo-saml-enable-auto-redirect">
		<form name="mosaml_site_auto_redirection" id="mosaml_site_auto_redirection" method="post" action="">
			<?php wp_nonce_field( 'mosaml_site_auto_redirection' ); ?>
			<input type="hidden" name="option" value="mosaml_site_auto_redirection">
			<?php Feature_Control::start_feature_lock_container( 2 ); ?>
			<label class="switch">
				<input type="checkbox" name="mo_saml_enable_auto_redirect" id="mo_saml_enable_auto_redirect" <?php echo esc_attr( $disable_site_auto_redirect_toggle ); ?> value="checked" onchange="moSamlToggleAutoRedirect(this);" 
				<?php echo esc_attr( $site_auto_redirection_data->enable_site_auto_redirect ); ?> >
				<span class="slider round"></span>
			</label>
			<span class="mo-saml-5px-padding-left"><b>Enable Auto Redirect from Site</b></span>
			<?php Feature_Control::end_feature_lock_container( 2 ); ?>
			<?php echo( Feature_Control::is_feature_locked( 2 ) ? '<br>' : '' ); ?>
			<?php Feature_Control::start_feature_lock_container( 3 ); ?>
			<div class="mosaml-padding-top-1-rem">
				<table class="mosaml-redirection-from-site-table">
					<tr>
						<td class="mo-saml-redirection-from-site-td">
							<input type="radio" id="mo_saml_redirect_default_idp" name="mo_saml_auto_redirection_options" value="default_idp" onclick="submitAutoRedictionOptionForm();"
							<?php
							echo esc_attr( 'default_idp' === $site_auto_redirection_data->site_auto_redirection_option ? 'checked' : '' );
							echo ' ' . esc_attr( $disable_site_auto_redirect_options );
							?>
							>
							Redirect to default IDP if user not logged in
							<a class="mo_saml_description" id="redirect_default_idp">[What does this mean?]</a>
							<div hidden id="redirect_default_idp_desc" class="mo_saml_help_desc">
								<span>Select this option if you want to restrict your site to only logged in users. Selecting this option will redirect the users to your default IdP if logged in session is not found.</span>
							</div>
						</td>
					</tr>
				</table>
				<table class="mosaml-redirection-from-site-table">
					<tr>
						<td class="mo-saml-redirection-from-site-td">
							<input type="radio" id="mo_saml_registered_only_access" name="mo_saml_auto_redirection_options" value="wp_login" onclick="submitAutoRedictionOptionForm();"
							<?php
							echo esc_attr( 'wp_login' === $site_auto_redirection_data->site_auto_redirection_option ? 'checked' : '' );
							echo ' ' . esc_attr( $disable_site_auto_redirect_options );
							?>
							>
							Redirect to WordPress login page if user not logged in
							<a class="mo_saml_description" id="registered_only_access">[What does this mean?]</a>
							<div hidden id="registered_only_access_desc" class="mo_saml_help_desc">
								<span>Select this option if you want to restrict your site to only logged in users. Selecting this option will redirect the users to your WordPress Login page.</span>
							</div>
						</td>
					</tr>
				</table>
				<?php Feature_Control::start_feature_lock_container( 4 ); ?>
				<table class="mosaml-redirection-from-site-table">
					<tr>
						<td class="mo-saml-redirection-from-site-td">
							<input type="radio" id="mo_saml_auto_redirect_to_public_page" name="mo_saml_auto_redirection_options" value="public_page" onclick="submitAutoRedictionOptionForm();"
							<?php
							echo esc_attr( 'public_page' === $site_auto_redirection_data->site_auto_redirection_option ? 'checked' : '' );
							echo ' ' . esc_attr( $disable_site_auto_redirect_options );
							?>
							>
							Redirect to public page if user not logged in
							<a class="mo_saml_description" id="auto_redirect_access">[What does this mean?]</a>
							<div hidden id="auto_redirect_access_desc" class="mo_saml_help_desc">
								<span>If you are selecting this option then please specify the public page URL in the textbox below. All the users who are not logged into the site will be redirected to the URL mentioned in the following textbox if they will try to access any page of your site. Add the shortcode given below on that page. This will make the users select the IDP from that page.</span>
							</div>
						</td>
					</tr>
				</table>
				<table class="mosaml-redirection-from-site-table">
					<tr>
						<td class="mo-saml-redirection-from-site-td-url-label" style="padding-left: 40px;" >Public Page URL:</td>
						<td class="mo-saml-redirection-from-site-td-url-input">
							<input type="url" name="mo_saml_public_page_to_redirect" class="mo-saml-redirection-from-site-input" value="<?php echo esc_url( $site_auto_redirection_data->public_page_url ); ?>"
							<?php
							echo ' ' . esc_attr( $disable_public_page_url_options );
							?>
							required placeholder="Enter an URL to enable this auto-redirect feature">
						</td>
						<td>
							<input type="submit" value="Save" class="button button-primary button-large mo-saml-submit-button-width"
							<?php
							echo ' ' . esc_attr( $disable_public_page_url_options );
							?>
							/>
						</td>
					</tr>
					<tr>
						<td></td>
						<td class="mo-saml-redirection-from-site-td-url-note"><b>Note:</b> If this URL is set, users will always be redirected to this URL (if you select the <b>Auto-redirect to the public page of the site</b> option) if they try to access any page before login.</td>
						<td></td>
					</tr>
				</table>
				<?php Feature_Control::end_feature_lock_container( 4 ); ?>
			</div>
			<?php Feature_Control::end_feature_lock_container( 3 ); ?>
		</form>
	</div>

	<?php echo( Feature_Control::is_feature_locked( 2 ) ? '<br>' : '' ); ?>
	<?php Feature_Control::start_feature_lock_container( 2 ); ?>
	
	<div class="mosaml-padding-top-bottom-1-rem" id="mo-saml-rss-feeds-div">
		<form id="mo_saml_enable_rss_access_form" method="post" action="">
			<?php wp_nonce_field( 'mosaml_rss_feed_access' ); ?>
			<input type="hidden" name="option" value="mosaml_rss_feed_access" />
			<label class="switch">
				<input type="checkbox" name="mo_saml_enable_rss_access" <?php echo esc_attr( $disable_rss_feed_access_toggle ); ?> value="checked"
				<?php echo esc_attr( $rss_feed_access_data->enable_rss_feed_access ); ?>/>
				<span class="slider round"></span>
			</label>
			<span class="mo-saml-5px-padding-left"><b>Enable access to RSS Feeds</b></span>
			<a class="mo_saml_description" id="rss_feed_toggle">[What does this mean?]</a>
			<br>
			<div hidden id="rss_feed_toggle_info" class="mo_saml_help_desc">
				<span>By enabling this feature the users will be able to access the RSS URL of the WordPress site even while the Auto-redirect feature is enabled.</span>
			</div>
		</form>
	</div>
	
	<div class="mosaml-padding-top-bottom-1-rem" id="mo-saml-force-authentication-div">
		<form id="mo_saml_force_authentication_form" method="post" action="">
			<?php wp_nonce_field( 'mosaml_force_authentication' ); ?>
			<input type="hidden" name="option" value="mosaml_force_authentication" />
			<label class="switch">
				<input type="checkbox" name="mo_saml_force_authentication" <?php echo esc_attr( $disable_force_authentication_toggle ); ?> id="mo_saml_force_authentication" value="true"
				<?php echo esc_attr( $force_authentication_enabled ? 'checked' : '' ); ?>/>
				<span class="slider round"></span>
			</label>
			<span class="mo-saml-5px-padding-left"><b>Force authentication with your IdP on each login attempt</b></span>
			<a class="mo_saml_description" id="force_authentication_with_idp">[What does this mean?]</a>
			<br>
			<div hidden id="force_authentication_with_idp_desc" class="mo_saml_help_desc">
				<span>It will force user to provide credentials on your IdP on each login attempt even if the user is already logged in to IdP. This option may require some additional setting in your IdP to force it depending on your Identity Provider.</span>
			</div>
		</form>
	</div>

	<?php Feature_Control::end_feature_lock_container( 2 ); ?>
	<?php echo( Feature_Control::is_feature_locked( 2 ) ? '<br>' : '' ); ?>
</div>
<br> 
