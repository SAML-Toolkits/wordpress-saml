<?php
/**
 * Attribute Mapping Subtab Template
 *
 * This template renders the attribute mapping form using data from the Attribute_Mapping_DTO.
 *
 * @package MOSAML
 * @since 1.0.0
 */
// phpcs:ignoreFile WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedVariableFound -- Template scope variables.

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\SRC\Constant\Constants;
use MOSAML\SRC\Constant\Plugin_Files_Constants;
use MOSAML\SRC\Utils\Feature_Control;

?>

<form name="mosaml_attribute_mapping_form" method="post" action="<?php echo esc_url( $attribute_mapping_subtab_url ); ?>" class="mo_saml_attribute_role_table">
	<?php wp_nonce_field( 'mosaml_attribute_mapping_form' ); ?>
	<input type="hidden" name="option" value="mosaml_attribute_mapping_form">
	<input type="hidden" name="selected_idp_name" value="<?php echo esc_attr( $selected_idp ); ?>">
	
	[ <a target="_blank" href="<?php echo esc_url( Constants::ATTRIBUTE_MAPPING_DOC_URL ); ?>">Click here</a> to know how this is useful. ]<br><br>

	<div class="mosaml-tab-content-section mosaml-no-border-bottom">
		<span class="mo-saml-heading"><b>Map Basic Attributes</b></span>
		<hr>
		<?php Feature_Control::start_feature_lock_container( 2 ); ?>
		<table class=" mosaml-table-width">
			<tbody>
				<tr>
					<td colspan="4"></td>
				</tr>
				<tr>
					<td colspan="2" class="mo_saml_role_mapping_table">
						<strong>Username <span class="mo-saml-required-asterisk">*</span></strong>
					</td>
					<td class="mo_saml_role_table_data">
						<?php
						$field_name      = 'user_name';
						$field_label     = 'Username';
						$current_value   = ! empty( $data->user_name ) ? $data->user_name : 'NameID';
						$test_attributes = $test_config_attributes;
						$is_required     = true;
						$disabled        = $disabled ? true : null;
						require Plugin_Files_Constants::ATTRIBUTE_DROPDOWN;
						?>
					</td>
				</tr>
				<tr>
					<td colspan="2" class="mo_saml_role_mapping_table">
						<strong>Email <span class="mo-saml-required-asterisk">*</span></strong>
					</td>
					<td class="mo_saml_role_table_data">
						<?php
						$field_name    = 'email';
						$field_label   = 'Email';
						$current_value = ! empty( $data->email ) ? $data->email : 'NameID';
						$is_required   = true;
						require Plugin_Files_Constants::ATTRIBUTE_DROPDOWN;
						?>
					</td>
				</tr>
				<tr>
					<td colspan="2" class="mo_saml_role_mapping_table">
						<strong>First Name</strong>
					</td>
					<td class="mo_saml_role_table_data">
						<?php
						$field_name    = 'first_name';
						$field_label   = 'First Name';
						$current_value = ! empty( $data->first_name ) ? $data->first_name : '';
						$is_required   = false;
						require Plugin_Files_Constants::ATTRIBUTE_DROPDOWN;
						?>
					</td>
				</tr>
				<tr>
					<td colspan="2" class="mo_saml_role_mapping_table">
						<strong>Last Name</strong>
					</td>
					<td class="mo_saml_role_table_data">
						<?php
						$field_name    = 'last_name';
						$field_label   = 'Last Name';
						$current_value = ! empty( $data->last_name ) ? $data->last_name : '';
						$is_required   = false;
						require Plugin_Files_Constants::ATTRIBUTE_DROPDOWN;
						?>
					</td>
				</tr>
				<tr>
					<td colspan="2" class="mo_saml_role_mapping_table">
						<strong>Nickname</strong>
					</td>
					<td class="mo_saml_role_table_data">
						<?php
						$field_name    = 'nick_name';
						$field_label   = 'Nickname';
						$current_value = ! empty( $data->nick_name ) ? $data->nick_name : '';
						$is_required   = false;
						require Plugin_Files_Constants::ATTRIBUTE_DROPDOWN;
						?>
					</td>
				</tr>
				<tr>
					<td colspan="2" class="mo_saml_role_mapping_table">
						<strong>Display Name</strong>
					</td>
					<td class="mo_saml_role_table_data">
						<select name="mo_saml_display_name" class="mo-saml-attr-input-width" <?php echo esc_attr( ( $disabled ) ? 'disabled' : '' ); ?>>
							<?php $display_name = ! empty( $data->display_name ) ? $data->display_name : ( 4 !== MOSAML_VERSION ? 'USERNAME' : '' ); ?>
							<option value="USERNAME" <?php selected( $display_name, 'USERNAME' ); ?>>Username</option>
							<option value="EMAIL" <?php selected( $display_name, 'EMAIL' ); ?>>Email</option>
							<option value="FNAME" <?php selected( $display_name, 'FNAME' ); ?>>First Name</option>
							<option value="LNAME" <?php selected( $display_name, 'LNAME' ); ?>>Last Name</option>
							<option value="NICKNAME" <?php selected( $display_name, 'NICKNAME' ); ?>>Nickname</option>
							<option value="FNAME_LNAME" <?php selected( $display_name, 'FNAME_LNAME' ); ?>>FirstName LastName</option>
							<option value="LNAME_FNAME" <?php selected( $display_name, 'LNAME_FNAME' ); ?>>LastName First Name</option>
						</select>
					</td>
				</tr>
				<tr>
					<td colspan="2" class="mo_saml_role_mapping_table"></td>
					<td class="mo_saml_role_table_data">
						<label class="switch">
						<input type="checkbox" name="mo_saml_do_not_update_display_name" value="checked" 
							<?php 
								checked( ( ! empty( $data->do_not_update_display_name ) ? $data->do_not_update_display_name : '' ), 'checked' ); 
							    echo esc_attr( ( $disabled ) ? 'disabled' : '' ); 
							?>
						>
						<span class="slider round"></span>
						</label>
						<span><b>Do not update existing User's Display Name</b></span><br>
						Note: Check this option if you do not want to update the existing user's display name attribute.
					</td>
				</tr>
			</tbody>
		</table>
		<?php Feature_Control::end_feature_lock_container( 2 ); ?>
	</div>

	<div class="mosaml-tab-content-section">
		<span class="mo-saml-heading"><b>Map Custom Attributes</b></span><hr>
		<div class="mo-saml-note">
				<b>NOTE: </b>Custom Attribute Mapping means you can map any attribute of the IDP to the attributes of <b>user-meta</b> table of your database.<br>
				Enable the toggle <b>Display Attribute</b> for an attribute if you want to display it in the <a href="<?php echo esc_url( admin_url( 'users.php' ) ); ?>">WordPress Users</a> table.
		</div>
		<br>
		<?php Feature_Control::start_feature_lock_container( 3 ); ?>
		<table class=" mosaml-table-width">
			<tbody>
				<tr>
					<td colspan="2">
						<input type="button" name="add_attribute" value="Add New Attribute" <?php echo esc_attr( $disable_due_to_no_idp ); ?> onclick="add_custom_attribute( <?php echo esc_attr( wp_json_encode( is_array( $test_config_attributes ) ? $test_config_attributes : array() ) ); ?> );" class="button button-primary button-large"><br><br>
					</td>
				</tr>
				<tr>
					<td class="mosaml-text-align-center mo-saml-width-30"><b>Custom Attribute Name</b></td>
					<td class="mosaml-text-align-center mo-saml-width-50"><b>Attribute Name from IDP</b></td>
					<td class="mosaml-text-align-center mo-saml-width-15"><b>Display Attribute</b></td>
					<td></td>
				</tr>
				
				<?php if ( ! empty( $data->custom_attributes ) && is_array( $data->custom_attributes ) ) : ?>
					<?php foreach ( $data->custom_attributes as $index => $attr ) : ?>
						<tr class="custom-attr-rows">
							<td>
								<input type="text" class="mosaml-width-100" name="mo_saml_custom_attr_keys[]" <?php echo esc_attr( $disable_due_to_no_idp ); ?> placeholder="Custom attribute name" value="<?php echo esc_attr( $attr['name'] ); ?>">
							</td>
							<td class="mo-saml-padding-left-10px">
								<?php
								$field_name        = 'custom_attr_values[]';
								$field_label       = 'IDP';
								$current_value     = $attr['value'];
								$test_attributes   = $test_config_attributes;
								$is_required       = false;
								$placeholder       = 'Enter IDP attribute name';
								$custom_field_name = 'mo_saml_custom_attr_values[]';
								$width_class       = 'mosaml-width-100';
								$disabled          = ( $disabled ) ? true : null;
								include Plugin_Files_Constants::ATTRIBUTE_DROPDOWN;
								?>
							</td>
							<td class="mosaml-text-align-center">
								<label class="switch mo-saml-toggle-label">
									<input type="checkbox" name="mo_saml_show_custom_attrs[]" <?php echo esc_attr( $disable_due_to_no_idp ); ?> value="<?php echo esc_attr( $index ); ?>" <?php checked( $attr['display'], true ); ?>>
									<span class="slider round"></span>
								</label>
							</td>
							<td class="mo-saml-padding-left-10px">
								<input type="button" value="X" onclick="remove_row(this);" class="button button-primary button-large" <?php echo esc_attr( $disable_due_to_no_idp ); ?>>
							</td>
						</tr>
					<?php endforeach; ?>
				<?php else : ?>
					<tr class="custom-attr-rows">
						<td>
							<input type="text" class="mosaml-width-100" name="mo_saml_custom_attr_keys[]" <?php echo esc_attr( $disable_due_to_no_idp ); ?> placeholder="Custom attribute name" value="">
						</td>
						<td class="mo-saml-padding-left-10px">
							<?php
							$field_name        = 'custom_attr_values[]';
							$field_label       = 'IDP';
							$current_value     = '';
							$test_attributes   = $test_config_attributes;
							$is_required       = false;
							$placeholder       = 'Enter IDP attribute name';
							$custom_field_name = 'mo_saml_custom_attr_values[]';
							$disabled          = ( $disabled ) ? true : null;
							$width_class       = 'mosaml-width-100';
							include Plugin_Files_Constants::ATTRIBUTE_DROPDOWN;
							?>
						</td>
						<td class="mosaml-text-align-center">
							<label class="switch mo-saml-toggle-label">
								<input type="checkbox" name="mo_saml_show_custom_attrs[]" <?php echo esc_attr( $disable_due_to_no_idp ); ?> value="0">
								<span class="slider round"></span>
							</label>
						</td>
						<td class="mo-saml-padding-left-10px">
							<input type="button" value="X" onclick="remove_row(this);" class="button button-primary button-large" <?php echo esc_attr( $disable_due_to_no_idp );?>/>
						</td>
					</tr>
				<?php endif; ?>
				
				<tr id="save_config_element">
				</tr>
			</tbody>
		</table>
		<?php Feature_Control::end_feature_lock_container( 3 ); ?>
	</div>

	<div class="mo-saml-form-submit-container">
		<br>
		<input type="submit" name="submit" value="Save" <?php echo esc_attr( $disable_due_to_no_idp ); ?> class="button button-primary button-large mo-saml-submit-button-width" <?php echo esc_attr( Feature_Control::get_disabled_attribute( 2 ) ); ?>>
	</div>
</form>

