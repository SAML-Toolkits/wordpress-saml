<?php
/**
 * Widget Settings Template
 *
 * @package miniorange-saml-20-single-sign-on
 */
// phpcs:ignoreFile WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedVariableFound -- Template scope variables.

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\SRC\Utils\Feature_Control;
use MOSAML\SRC\Utils\Utility;

?>

<div class="mo-saml-settings-container" id="mo-saml-shortcode-widget">
	<h3>
		Shortcode & Widget Settings
	</h3>
	<hr>
	<div class="mo-saml-settings-internal-container">
		<p>You can add the SSO login button on your site using either a <b>Widget</b> or a <b>Shortcode</b>.</p>

		<h4>1. Add the SSO Widget on your site by following these steps:</h4>
			<?php
			$theme_supports_widgets = current_theme_supports( 'widgets' );
			if ( ! $theme_supports_widgets ) :
				?>
				<div class="mosaml-widget-disable-strip">
					The current theme does not support widgets. Please switch to a theme that supports widgets or contact your theme developer to enable widget support.
				</div>
			<?php endif; ?>
			<ol>
				<li>Go to Appearances > <a href="<?php echo esc_url( $admin_url ); ?>widgets.php"> Widgets.</a></li>
				<li>Select the <b>miniOrange SAML Login widget</b>. Drag and drop to your favourite location and save.</li>
				<li>This will add the login links of all IdPs you have configured and enabled.</li>
			</ol>
		</br>
		<h4>2. Using the Shortcode</h4>
		<ol>
			<p>Use the following <b>IDP Specific shortcode</b> to show a login button for a specific IdP:</p>
			<table>
				<tr>
					<td>For PHP page:</td>
					<td>
						<code>
							echo do_shortcode('[MO_SAML_FORM idp="<?php echo esc_attr( $idp_id ); ?>"]');
						</code>
					</td>
				</tr>
				<tr>
					<td>For HTML page:</td>
					<td>
						<code>[MO_SAML_FORM idp="<?php echo esc_attr( $idp_id ); ?>"]</code>
					</td>
				</tr>
			</table>
		</ol>
		<br/>
		<div>
			<h3>Customize Shortcode & Widget Text</h3>
			<?php Feature_Control::start_feature_lock_container( 2 ); ?>
			<form id="mo_saml_widget_form" method="post" action="">
				<?php wp_nonce_field( 'mosaml_login_shortcode_widget_saml_settings' ); ?>
				<input type="hidden" name="option" value="mosaml_login_shortcode_widget_saml_settings" /> 
				<input type="hidden" name="saml_save_settings_action" value="custom"/>			
				<input type="hidden" name="sso_link_idp" value="<?php echo esc_attr( $id ); ?>">
				<table class="mo-saml-widget-table">
					<tr>
						<td><b>Login text:</b></td>
						<td><input type="text" id="mo_saml_custom_login_text" class="mo-saml-widget-input" name="mo_saml_custom_login_text" <?php echo esc_attr( $disable_due_to_no_idp ); ?> placeholder="Login with <?php echo esc_attr( $idp_name ); ?>" value="<?php echo esc_attr( isset( $shortcode_widget_value->widget_config['custom_login_text'] ) ? $shortcode_widget_value->widget_config['custom_login_text'] : '' ); ?>"></td>
					</tr>
					<tr>
						<td><b>Greeting text:</b></td>
						<td><input type="text" id="mo_saml_custom_greeting_text" class="mo-saml-widget-greeting-input" name="mo_saml_custom_greeting_text" <?php echo esc_attr( $disable_due_to_no_idp ); ?> placeholder="Hello," value="<?php echo esc_attr( isset( $shortcode_widget_value->widget_config['custom_greeting_text'] ) ? $shortcode_widget_value->widget_config['custom_greeting_text'] : '' ); ?>">&nbsp
							<select name="mo_saml_greeting_name" id="mo_saml_greeting_name" class="mo-saml-widget-select" <?php echo esc_attr( $disable_due_to_no_idp ); ?>>
								<option value="USERNAME" <?php echo ( ( isset( $shortcode_widget_value->widget_config['greeting_name'] ) ? $shortcode_widget_value->widget_config['greeting_name'] : '' ) == 'USERNAME' ) ? 'selected="selected"' : ''; ?>>Username</option>
								<option value="EMAIL" <?php echo ( ( isset( $shortcode_widget_value->widget_config['greeting_name'] ) ? $shortcode_widget_value->widget_config['greeting_name'] : '' ) == 'EMAIL' ) ? 'selected="selected"' : ''; ?>>Email</option>
								<option value="FNAME" <?php echo ( ( isset( $shortcode_widget_value->widget_config['greeting_name'] ) ? $shortcode_widget_value->widget_config['greeting_name'] : '' ) == 'FNAME' ) ? 'selected="selected"' : ''; ?>>FirstName</option>
								<option value="LNAME" <?php echo ( ( isset( $shortcode_widget_value->widget_config['greeting_name'] ) ? $shortcode_widget_value->widget_config['greeting_name'] : '' ) == 'LNAME' ) ? 'selected="selected"' : ''; ?>>LastName</option>
								<option value="FNAME_LNAME" <?php echo ( ( isset( $shortcode_widget_value->widget_config['greeting_name'] ) ? $shortcode_widget_value->widget_config['greeting_name'] : '' ) == 'FNAME_LNAME' ) ? 'selected="selected"' : ''; ?>>FirstName LastName</option>
								<option value="LNAME_FNAME" <?php echo ( ( isset( $shortcode_widget_value->widget_config['greeting_name'] ) ? $shortcode_widget_value->widget_config['greeting_name'] : '' ) == 'LNAME_FNAME' ) ? 'selected="selected"' : ''; ?>>LastName FirstName</option>
							</select>
						</td>
					</tr>
					<tr>
						<td><b>Logout text:</b></td>
						<td><input type="text" id="mo_saml_custom_logout_text" class="mo-saml-widget-input" name="mo_saml_custom_logout_text" <?php echo esc_attr( $disable_due_to_no_idp ); ?> placeholder="Logout" value="<?php echo esc_attr( isset( $shortcode_widget_value->widget_config['custom_logout_text'] ) ? $shortcode_widget_value->widget_config['custom_logout_text'] : '' ); ?>"></td>
					</tr>
					<tr></tr>
					<tr>
						<td></td>
						<td>
							<input type="submit" value="Save" class="button button-primary button-large mo-saml-submit-button-width" <?php echo esc_attr( $disable_due_to_no_idp ); ?>/>
						</td>
					</tr>
				</table>
			</form>
			<?php Feature_Control::end_feature_lock_container( 2 ); ?>
		</div>
		<br>
		<?php
			static $discovery_flow_rendered = false;
			if ( $is_enterprise && ! $discovery_flow_rendered ) {
				$discovery_flow_rendered = true; // Prevent showing this section again.
				Feature_Control::start_feature_lock_container( 4 );
				?>
				<hr>
				<h3>Discovery flow ( Configured Active IDPs in a dropdown )</h3>
				<form id="mosaml_shortcode_form" method="post" action="">
					<?php wp_nonce_field( 'mosaml_shortcode_option' ); ?>
					<input type="hidden" name="option" value="mosaml_shortcode_option"/>
					<input type="hidden" name="sso_link_idp" value="<?php echo esc_attr( $id ); ?>">
					<table>
						<tr>
							<td>
								For PHP page:
							</td>
							<td>
								<code>echo do_shortcode('[MO_SAML_IDP_LIST]');</code>
							</td>
						</tr>
						<tr>
							<td>
								For HTML page:
							</td>
							<td><code>[MO_SAML_IDP_LIST]</code></td>
						</tr>
						<tr>
							<td class="mo-saml-shortcode-table-cell-40">
								Shortcode Login text for List:
							</td>
							<td>

							<input type="text" placeholder="Login with SSO" id="mo_saml_shortcode_login_text" class="mo-saml-shortcode-input-field" title="This text will be displayed on the left side of the IDP dropdown list" name="mo_saml_shortcode_login_text" value="<?php echo esc_attr( $shortcode_value->shortcode_login_text ); ?>" <?php echo esc_attr( $disable_due_to_no_idp ); ?> >
								<input type="submit" value="Save" class="button button-primary button-large mo-saml-submit-button-width" <?php echo esc_attr( $disable_due_to_no_idp ); ?>/>
							</td>
						</tr>
					</table>
				</form>
				</br>
				<?php
				Feature_Control::end_feature_lock_container( 4 );
			}
		?>
	</div>
</div>
