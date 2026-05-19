<?php
/**
 * Account Login form template.
 *
 * @package miniorange-saml-20-single-sign-on/template/account-settings
 */
// phpcs:ignoreFile WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedVariableFound -- Template scope variables.

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\SRC\Constant\URL_Constants;

?>

<div class="mosaml-tab-content-section mosaml-margin-top-bottom-0-2-rem">
	<form name="account_login" method="post" action="">
		<?php wp_nonce_field( 'mosaml_verify_customer' ); ?>
		<input type="hidden" name="option" value="mosaml_verify_customer" />
		<div class="mo_saml_table_layout">

			<h3>Login with miniOrange</h3>
			<p>
				<b>
					<a href="<?php echo esc_url( URL_Constants::PORTAL_FORGOT_PASSWORD_URL ); ?>" target="_blank">Click here if you forgot your password?</a>
				</b>
			</p>
			<br/>

		<table class="mo_saml_settings_table">
			<tr>
				<td><b>Email</b><span class="mosaml-required-field">*</span></td>
				<td><input class="mo_saml_table_textbox" type="email" name="email"
					required placeholder="person@example.com"
					value="<?php esc_html( get_option( 'mo_saml_admin_email' ) ); ?>" /></td>
			</tr>
			
			<tr>
				<td><b>Password</b><span class="mosaml-required-field">*</span></td>
				<td><input class="mo_saml_table_textbox" required type="password"
					name="password" placeholder="Choose your password"
					minlength="6" title="Minimum 6 characters should be present. Maximum 15 characters should be present. Only following symbols (!@#.$%^&*-_) should be present"
					/></td>
			</tr>
			<tr style="height: 20px;">
				<td colspan="2">&nbsp;</td>
			</tr>
			<tr>
				<td></td>
				<td>
					<input type="submit" name="submit" value="Login"
					class="button button-primary button-large" />
					<?php
					if ( $is_free ) {
						$login_url = add_query_arg(
							array(
								'page'   => 'mo_saml_settings',
								'tab'    => 'account_settings',
								'subtab' => 'account-register',
							),
							admin_url( 'admin.php' )
						);
						?>
						<a href="<?php echo esc_url( $login_url ); ?>" class="button button-primary button-large mo-saml-alredy-have-btn">
							<?php esc_html_e( 'New here? Register', 'miniorange-saml-20-single-sign-on' ); ?>
						</a>
						<?php
					}
					?>
				</td>
			</tr>
		</table>
	</div>
</form>
</div>


