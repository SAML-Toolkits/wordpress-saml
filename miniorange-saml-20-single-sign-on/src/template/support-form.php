<?php
/**
 * Support form template.
 *
 * @package miniorange-saml-20-single-sign-on/template
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\SRC\Constant\Constants;

?>

<div class="mosaml-tab-content-section mosaml-margin-top-bottom-0-2-rem">
	<h3>Support</h3>
	<p>Need any help? We can help you with configuring your Identity Provider. Just send us a query and we will get back to you soon.</p>
	<form method="post" action="">
		<?php wp_nonce_field( 'mosaml_contact_us_query_option' ); ?>
		<input type="hidden" name="option" value="mosaml_contact_us_query_option" />
		<table class="mo_saml_settings_table">
			<tr>
				<td><input type="email" class="mosaml-input-field" required name="mosaml_contact_us_email" value="<?php echo esc_attr( $admin_email ?? '' ); ?>" placeholder="Enter your email"></td>
			</tr>
			<tr>
				<td><input type="tel" id="contact_us_phone" class="mosaml-input-field" name="mosaml_contact_us_phone" value="<?php echo esc_attr( $admin_phone ?? '+1' ); ?>" placeholder="Enter your phone"></td>
			</tr>
			<tr>
				<td><textarea class="mosaml-input-field" required name="mosaml_contact_us_query" rows="4" style="resize: vertical;" placeholder="Write your query here"></textarea></td>
			</tr>
			<tr>
				<td><br/></td>
			</tr>
			<tr>
				<td>
					<label class="switch">
						<input type="checkbox" name="<?php echo esc_attr( Constants::SEND_PLUGIN_CONFIG_OPTION_NAME ); ?>" id="<?php echo esc_attr( Constants::SEND_PLUGIN_CONFIG_OPTION_NAME ); ?>" value="checked" <?php echo esc_attr( get_option( Constants::SEND_PLUGIN_CONFIG_OPTION_NAME ) ); ?>/>
						<span class="slider round"></span>
					</label>
					<span style="padding-left:5px"><b>Send plugin configuration with the query</b></span>
				</td>
			</tr>
			<tr>
				<td><br/></td>
			</tr>
			<tr class="mosaml-align-ele-center">
				<td class="mosaml-align-ele-center"><input type="submit" name="submit" class="button button-primary button-large" value="Submit"/></td>
			</tr>
		</table>
	</form>
</div>
