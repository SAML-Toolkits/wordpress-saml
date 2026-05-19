<?php
/**
 * Account Info form template.
 *
 * @package miniorange-saml-20-single-sign-on/template
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

?>
<div class="mosaml-tab-content-section mosaml-margin-top-bottom-0-2-rem">
	<section>
		<div class="mo_saml_account_info_free_header">
			<h3>Account Details</h3>
			<div>
				<input type="button" name="mo_saml_remove_account" id="mo_saml_remove_account" class="button button-large mo-saml-remove-license" value="Remove Account" onclick="mo_saml_free_up_license_key()">
			</div>
		</div>
		<br>
		<table class="mo_saml_settings_table">
			<tr style="border: 0.5px solid #fff;background: #e9f0ff;">
				<td class="mo_saml_table_cell" style="width:30%; padding: 15px;"><b><?php esc_html_e( 'miniOrange Account Email', 'miniorange-saml-20-single-sign-on' ); ?></b></td>
				<td class="mo_saml_table_cell" style="width:30%; padding: 15px;"><b><?php echo esc_html( $customer_email ); ?></b></td>
			</tr>
			<tr style="border: 0.5px solid #fff;background: #e9f0ff;">
				<td class="mo_saml_table_cell" style="width:30%; padding: 15px;"><b><?php esc_html_e( 'Customer ID', 'miniorange-saml-20-single-sign-on' ); ?></b></td>
				<td class="mo_saml_table_cell" style="width:30%; padding: 15px;"><b><?php echo esc_html( $customer_id ); ?></b></td>
			</tr>		
		</table>
	<br/><br/>
	</section>

	<form name="f" method="post" action="" id="mo_saml_remove_account_form">
		<?php wp_nonce_field( 'mosaml_remove_account' ); ?>
		<input type="hidden" name="option" value="mosaml_remove_account"/>
	</form>
</div>
