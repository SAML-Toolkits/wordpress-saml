<?php
/**
 * SSO Button Subsection Template.
 *
 * @package miniorange-saml-20-single-sign-on
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\SRC\Utils\Feature_Control;

?>

<div class="mo-saml-sso-button-subsection">
	<?php Feature_Control::start_feature_lock_container( 4 ); ?>
	<form method="post" action="" id="mosaml_enable_hide_wp_login_form">
		<?php wp_nonce_field( 'mosaml_enable_hide_wp_login_option' ); ?>
		<input type="hidden" name="option" value="mosaml_enable_hide_wp_login_option" >
		<input type="hidden" name="sso_link_idp" value="<?php echo esc_attr( $id ); ?>">
		<p>
			<label class="switch">
						<input type="checkbox" name="mo_saml_enable_hide_wp_login" value="checked" onchange="submitHideWpLoginForm()" 
						<?php
						echo esc_attr( $hide_wp_login_value->hide_wp_login );
						echo esc_attr( $disable_due_to_no_idp );
						?>
						/>
				<span class="slider round"></span>
			</label>
			<span class="mo-saml-redirect-from-wp-login-label"><b>Hide/Disable WordPress Default Login Form</b></span>
			<a class="mo_saml_description" id="hide_wordpress_login">[What does this mean?]</a>
			<div hidden id="hide_wordpress_login_desc" class="mo_saml_help_desc">
				<span>Enabling this option will prevent users from accessing the default WordPress login form at</span>
				<br>
				
				<code><b><?php echo esc_url( $login_url ); ?></b></code> or
				<code><b><?php echo esc_url( $admin_url ); ?></b></code>
			</div>
		</p>
	</form>
	<?php Feature_Control::end_feature_lock_container( 4 ); ?>
	
	<form method="post" action="">
		<?php wp_nonce_field( 'mosaml_sso_button_options' ); ?>
		<input type="hidden" name="option" value="mosaml_sso_button_options" >
		<input type="hidden" name="sso_link_idp" value="<?php echo esc_attr( $id ); ?>">
		<div id="mo_sso_button_setup">
			<p>
				<label class="switch">
					<input type="checkbox" name="mo_saml_add_sso_button_wp" value="checked" <?php echo esc_attr( empty( $disabled ) ? $add_button_wp : 'disabled' ); ?> />
					<span class="slider round"></span>
				</label>
				<span class="mo-saml-sso-button-label"><b>Add a Single Sign on button on the WordPress login page</b></span>
			</p>
			<?php echo( Feature_Control::is_feature_locked( 3 ) ? '<br>' : '' ); ?>
			<?php Feature_Control::start_feature_lock_container( 3 ); ?>
			<p>
				<label class="switch">
					<input type="checkbox" name="mo_saml_use_button_as_shortcode" value="checked" 
					<?php
					checked( ( ! empty( $use_button_as_shortcode ) && 'checked' === $use_button_as_shortcode ), true );
					echo esc_attr( $disable_due_to_no_idp );
					?>
					/>
					<span class="slider round"></span>
				</label>
				<span class="mo-saml-sso-button-label"><b>Use this button as ShortCode</b></span>
			</p>
			<p>
				<label class="switch">
					<input type="checkbox" name="mo_saml_use_button_as_widget" value="checked" 
					<?php
					checked( ( ! empty( $use_button_as_widget ) && 'checked' === $use_button_as_widget ), true );
					echo esc_attr( $disable_due_to_no_idp );
					?>
					/>
					<span class="slider round"></span>
				</label>
				<span class="mo-saml-sso-button-label"><b>Use this button as Widget</b></span>
			</p>
			<br/>
			<h3 class="mo-saml-sso-button-heading">Customize Login Button:</h3>
			<table>
				<tr>
					<td class="mo-saml-width-200"><b>Shape</b></td>
					<td class="mo-saml-width-200"><b>Theme</b></td>
					<td class="mo-saml-width-200"><b>Size of Icons</b></td>
				</tr>
				<tr>
					<td class="mo-saml-width-200">
						<input type="radio" name="mo_saml_button_theme" id="mo_saml_button_theme_circle" value="circle" 
						<?php
						checked( 'circle' === $button_theme );
						echo esc_attr( $disable_due_to_no_idp );
						?>
						/> Round
					</td>
					<td class="mo-saml-width-250">
						<table>
							<tr>
								<td class="mo-saml-width-80">Button Color:</td>
								<td>
									<input id="mo_saml_button_color" type="text" class="mo-saml-width-135 color" name="mo_saml_button_color" data-jscolor="" value="<?php echo esc_attr( $button_color ); ?>" <?php echo esc_attr( $disable_due_to_no_idp ); ?> />
								</td>
							</tr>
						</table>
					</td>
					<td class="mo-saml-width-200">
						<table>
							<tr id="commonIcon">
								<td class="mo-saml-width-50-px">Size:</td>
								<td><input class="mo-saml-width-50-px" type="text" id="mo_saml_button_size" name="mo_saml_button_size" value="<?php echo esc_attr( $button_size ); ?>" <?php echo esc_attr( $disable_due_to_no_idp ); ?> /></td>
								<td><input id="decrease-size" type="button" class="button button-primary" value="-" <?php echo esc_attr( $disable_due_to_no_idp ); ?>/></td>
								<td><input id="increase-size" type="button" class="button button-primary" value="+" <?php echo esc_attr( $disable_due_to_no_idp ); ?>/></td>
							</tr>
							<tr class="longButton">
								<td class="mo-saml-width-50-px">Width:</td>
								<td><input class="mo-saml-width-50-px" type="text" id="mo_saml_button_width" name="mo_saml_button_width" value="<?php echo esc_attr( $button_width ); ?>" <?php echo esc_attr( $disable_due_to_no_idp ); ?> /></td>
								<td><input id="decrease-width" type="button" class="button button-primary" value="-" <?php echo esc_attr( $disable_due_to_no_idp ); ?>/></td>
								<td><input id="increase-width" type="button" class="button button-primary" value="+" <?php echo esc_attr( $disable_due_to_no_idp ); ?>/></td>
							</tr>
						</table>
					</td>
				</tr>
				<tr>
					<td class="mo-saml-width-200">
						<input type="radio" name="mo_saml_button_theme" id="mo_saml_button_theme_oval" value="oval" 
						<?php
						checked( 'oval' === $button_theme );
						echo esc_attr( $disable_due_to_no_idp );
						?>
						/> Rounded Edges
					</td>
					<td class="mo-saml-width-250">
						<table>
							<tr>
								<td class="mo-saml-width-80">Button Text:</td>
								<td>
									<input id="mo_saml_button_text" type="text" class="mo-saml-width-135" name="mo_saml_button_text" value="<?php echo esc_attr( $button_text ); ?>" placeholder="##IDP##" <?php echo esc_attr( $disable_due_to_no_idp ); ?>/>
								</td>
							</tr>
						</table>
					</td>
					<td class="mo-saml-width-200">
						<table>
							<tr class="longButton">
								<td class="mo-saml-width-50-px">Height:</td>
								<td><input class="mo-saml-width-50-px" type="text" id="mo_saml_button_height" name="mo_saml_button_height" value="<?php echo esc_attr( $button_height ); ?>" <?php echo esc_attr( $disable_due_to_no_idp ); ?>/></td>
								<td><input id="decrease-height" type="button" class="button button-primary" value="-" <?php echo esc_attr( $disable_due_to_no_idp ); ?>/></td>
								<td><input id="increase-height" type="button" class="button button-primary" value="+" <?php echo esc_attr( $disable_due_to_no_idp ); ?>/></td>
							</tr>
						</table>
					</td>
				</tr>
				<tr>
					<td class="mo-saml-width-200">
						<input type="radio" name="mo_saml_button_theme" id="mo_saml_button_theme_square" value="square" 
						<?php
						checked( 'square' === $button_theme );
						echo esc_attr( $disable_due_to_no_idp );
						?>
						/> Square
					</td>
					<td class="mo-saml-width-250">
						<table>
							<tr>
								<td class="mo-saml-width-80">Font Color:</td>
								<td>
									<input id="mo_saml_font_color" type="text" class="mo-saml-width-135 color" name="mo_saml_font_color" data-jscolor="" value="<?php echo esc_attr( $font_color ); ?>" <?php echo esc_attr( $disable_due_to_no_idp ); ?> />
								</td>
							</tr>
						</table>
					</td>
					<td class="mo-saml-width-200">
						<table>
							<tr class="longButton">
								<td class="mo-saml-width-50-px">Curve:</td>
								<td><input class="mo-saml-width-50-px" type="text" id="mo_saml_button_curve" name="mo_saml_button_curve" value="<?php echo esc_attr( $button_curve ); ?>" <?php echo esc_attr( $disable_due_to_no_idp ); ?> /></td>
								<td><input id="decrease-curve" type="button" class="button button-primary" value="-" <?php echo esc_attr( $disable_due_to_no_idp ); ?>/></td>
								<td><input id="increase-curve" type="button" class="button button-primary" value="+" <?php echo esc_attr( $disable_due_to_no_idp ); ?>/></td>
							</tr>
						</table>
					</td>
				</tr>
				<tr>
					<td class="mo-saml-width-200">
						<input type="radio" id="longButtonWithText" name="mo_saml_button_theme" value="longbutton" 
						<?php
						checked( 'longbutton' === $button_theme );
						echo esc_attr( $disable_due_to_no_idp );
						?>
						/> Long Button with Text
					</td>
					<td class="mo-saml-width-250">
						<table>
							<tr>
								<td class="mo-saml-width-80">Font Size:</td>
								<td>
									<table>
										<tr class="mo-saml-width-135">
											<td><input id="mo_saml_font_size" type="text" class="mo-saml-width-64" name="mo_saml_font_size" value="<?php echo esc_attr( $font_size ); ?>" <?php echo esc_attr( $disable_due_to_no_idp ); ?>/></td>
											<td><input id="decrease-font-size" type="button" class="button button-primary" value="-" <?php echo esc_attr( $disable_due_to_no_idp ); ?>/></td>
											<td><input id="increase-font-size" type="button" class="button button-primary" value="+" <?php echo esc_attr( $disable_due_to_no_idp ); ?>/></td>
										</tr>
									</table>
								</td>
							</tr>
						</table>
					</td>
				</tr>
			</table>
			<br/>
			<div><b>Position of Login Button on WordPress Login Page : </b>
				<table class="mo-saml-padding-top-4">
					<tr>
						<td class="mo-saml-width-200"><input type="radio" name="sso_button_login_form_position" value="above" 
						<?php
						checked( 'above' === $sso_button_position );
						echo esc_attr( $disable_due_to_no_idp );
						?>
						/> Above WP Login Form</td>
						<td class="mo-saml-width-200"><input type="radio" name="sso_button_login_form_position" value="below" 
						<?php
						checked( 'below' === $sso_button_position );
						echo esc_attr( $disable_due_to_no_idp );
						?>
						/> Below WP Login Form</td>
					</tr>
				</table>
			</div>
			<h3>Preview:</h3>
			<div class="mo-saml-padding-left-20">
				<a><button type="button" class="sso_button"></button></a>
			</div>
			<?php Feature_Control::end_feature_lock_container( 3 ); ?>
			<br/>
			<br/>
			<div class="mo-saml-sso-button-submit-container"><input type="submit" value="Save" class="button button-primary button-large mo-saml-submit-button-width" <?php echo esc_attr( $disable_due_to_no_idp ); ?> <?php echo esc_attr( $disabled_due_to_license ); ?> /></div>

		</div>
	</form>
</div>
