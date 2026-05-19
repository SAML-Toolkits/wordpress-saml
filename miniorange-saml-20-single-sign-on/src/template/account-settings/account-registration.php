<?php
/**
 * Account Registration form template.
 *
 * @package miniorange-saml-20-single-sign-on/template
 */
// phpcs:ignoreFile WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedVariableFound -- Template scope variables.

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

?>
<div class="mosaml-tab-content-section mosaml-margin-top-bottom-0-2-rem">
	<form name="mosaml_register_customer" method="post" action="">
		<?php wp_nonce_field( 'mosaml_register_customer' ); ?>
		<input type="hidden" name="option" value="mosaml_register_customer" />
		<div class="mo_saml_table_layout">
			<div id="toggle1">
				<h3>Register with miniOrange</h3>
			</div>
			<br/>
			<table class="mo_saml_settings_table">
				<tr>
					<td><b>Email<font color="#FF0000">* </font>:</b></td>
					<td><input class="mo_saml_table_textbox" type="email" name="registerEmail"
						required placeholder="person@example.com"
						value="" /></td>
				</tr>
				<tr>
					<td><b>Password<font color="#FF0000">* </font>:</b></td>
					<td><input class="mo_saml_table_textbox" required type="password"
						name="password" placeholder="Choose your password"
						minlength="6" title="Minimum 6 characters should be present. Maximum 15 characters should be present. Only following symbols (!@#.$%^&*-_) should be present"
					/></td>
				</tr>
				<tr>
					<td><b>Confirm Password<font color="#FF0000">* </font>:</b></td>
					<td><input class="mo_saml_table_textbox" required type="password"
						name="confirmPassword" placeholder="Confirm your password"
						minlength="6" title="Minimum 6 characters should be present. Maximum 15 characters should be present. Only following symbols (!@#.$%^&*-_) should be present"
					/></td>
				</tr>
				<tr>
					<td>&nbsp;</td>
					<td>
						<br>
						<input type="submit" name="submit" value="Register"
						class="button button-primary button-large" />
						<?php
						$login_url = add_query_arg(
							array(
								'page'   => 'mo_saml_settings',
								'tab'    => 'account_settings',
								'subtab' => 'account-login',
							),
							admin_url( 'admin.php' )
						);
						?>
						<a href="<?php echo esc_url( $login_url ); ?>" class="button button-primary button-large mo-saml-alredy-have-btn">
							<?php esc_html_e( 'Already have an account?', 'miniorange-saml-20-single-sign-on' ); ?>
						</a>
							
						<br><br>
					</td>
				</tr>
			</table>
		</div>
	</form>
</div>
