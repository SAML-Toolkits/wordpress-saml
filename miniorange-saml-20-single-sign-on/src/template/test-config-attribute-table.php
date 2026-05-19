<?php
/**
 * Test confguration attribute table template.
 *
 * @package miniorange-saml-20-single-sign-on/template
 */
// phpcs:ignoreFile WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedVariableFound -- Template scope variables.

use MOSAML\SRC\Utils\Utility;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

?>

<div class="mosaml-tab-content-section mosaml-margin-top-bottom-0-2-rem">
	<h3 class="mo-saml-heading">Attributes received from the Identity Provider:</h3>
	<div class="mo-saml-test-attrs-list">
		<table class="mosaml-table-width mosaml-table-layout mo-saml-idp-attrs-table">
			<thead>
				<tr>
					<th>Attribute Name</th>
					<th>Attribute Value</th>
				</tr>
			</thead>
			<tbody>
				<?php
				$test_config_attributes = ! empty( $idp_details->test_config_attributes ) ? maybe_unserialize( $idp_details->test_config_attributes ) : array();
				$test_config_attributes = is_array( $test_config_attributes ) ? $test_config_attributes : array();
				foreach ( $test_config_attributes as $attr_name => $attr_value ) {
					?>
					<tr>
						<td class="mo_saml_role_mapping_table"><?php echo esc_html( $attr_name ); ?></td>
						<td class="mo_saml_role_table_data">
							<?php
							echo is_array( $attr_value )
								? wp_kses( implode( '<hr>', $attr_value ), array( 'hr' => array() ) )
								: esc_html( $attr_value );
							?>
						</td>
					</tr>
					<?php
				}
				?>
			</tbody>
		</table>
	</div>
	<br>
	<input type="button" class="button-primary" value="Clear Attributes List" onclick="document.forms['clear_attrs_list_form'].submit();" <?php echo esc_attr( $disable_due_to_no_idp ); ?> />
	<p class="attrs-note">
		<strong>NOTE :</strong> Please clear this list after configuring the plugin to hide your
		confidential attributes.<br>
		Click on <strong>Test configuration</strong> for the respective IDP in IDP Configuration tab to populate the list again.
	</p>
	<form method="post" action="" id="clear_attrs_list_form">
		<?php wp_nonce_field( 'mosaml_clear_attrs_list' ); ?>
		<input type="hidden" name="idp_name" value="<?php echo esc_attr( $idp_details->id ); ?>">
		<input type="hidden" name="option" value="mosaml_clear_attrs_list">
	</form>
</div>
