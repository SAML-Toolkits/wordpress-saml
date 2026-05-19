<?php
/**
 * Role Mapping Subtab Template
 *
 * This template renders the role mapping form using data from the Role_Mapping_DTO.
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
use MOSAML\SRC\Utils\Utility;

?>

<form name="mosaml_role_mapping_form" method="post" action="" class="mo_saml_attribute_role_table">
	<?php wp_nonce_field( 'mosaml_role_mapping_form' ); ?>
	<input type="hidden" name="option" value="mosaml_role_mapping_form">
	<input type="hidden" name="selected_idp_id" value="<?php echo esc_attr( $selected_idp ); ?>">
	<?php Feature_Control::check_plugin_state(); ?>
	[ <a target="_blank" href="<?php echo esc_url( Constants::ROLE_MAPPING_DOC_URL ); ?>">Click here</a> to know how this is useful. ]<br><br>

	<div class="mosaml-tab-content-section mosaml-no-border-bottom">
		<?php Feature_Control::start_feature_lock_container( 3 ); ?>
		<table class=" mosaml-table-width mosaml-no-border-bottom">
			<tbody>
				<tr>
					<td colspan="2" class="mo_saml_role_mapping_table">
						<strong>IDP Group/Role Attribute <span class="mo-saml-required-asterisk">*</span></strong>
					</td>
					<td class="mo_saml_role_table_data">
						<?php
						$disabled = ( $disabled ) ? true : null;
						require_once Plugin_Files_Constants::ATTRIBUTE_DROPDOWN;
						?>
						<br><i>Select the IDP attribute to assign roles to Users.</i><br><br>
					</td>
				</tr>
				
				<?php
				foreach ( $wp_roles_names as $role_slug => $role_name ) :
					$role_value = ! empty( $role_mapping_values[ $role_slug ] ) ? $role_mapping_values[ $role_slug ] : '';
					?>
					<tr class="mo-saml-role-row">
						<td colspan="2" class="mo_saml_role_mapping_table">
							<strong><?php echo esc_html( $role_name ); ?></strong>
						</td>
						<td class="mo_saml_role_table_data">
							<input type="text" 
									name="mo_saml_role_value_<?php echo esc_attr( $role_slug ); ?>" 
									placeholder="Semi-colon(;) separated IDP group values" 
									class="mo-saml-attr-input-width" 
									<?php empty( $default_role_settings_data->group_attribute_name ) || isset( $disabled ) ? disabled( true ) : ''; ?>
									value="<?php echo esc_attr( $role_value ); ?>">
						</td>
					</tr>
				<?php endforeach; ?>
			</tbody>
		</table>
		<?php Feature_Control::end_feature_lock_container( 3 ); ?>
		<br><br>
		<span class="mo-saml-heading"><b><?php echo esc_html( MOSAML_VERSION < 3 ? 'Select Default User Role' : 'Select Action if Role Mapping Fails' ); ?></b></span><hr>
		<?php if ( MOSAML_VERSION >= 3 ) : ?>
		<div class="mo-saml-note">
			<b>NOTE: </b>These settings would be applied to users when the user's <b>IDP Group/Role value is not mapped</b> with any WordPress roles above.<br>
			<div class="mo-saml-test-steps">
				• If the toggle <b>Create New User with Role</b> is <b>disabled</b>, new users will not be created.<br>
				• If the toggle <b>Update Existing User with Role</b> is <b>enabled</b>, existing users role will be updated as per the selected default role. <br><br>
			</div>
		</div>
		<?php endif; ?>
		<table class="mosaml-table-width">
			<tbody>
				<tr>
					<td colspan="2" class="mo_saml_role_mapping_table">
						<br>
						<label class="switch">
							<input type="checkbox" name="mo_saml_create_new_user_with_role" id="mo_saml_create_new_user_with_role" value="checked" 
								<?php echo esc_attr( $new_user_role_toggle_value ); ?>
	 	 						<?php echo esc_attr( $new_user_role_toggle_disabled ); ?>
							>
							<span class="slider round"></span>
						</label>
						<span class="mo-saml-toggle-label"><strong>Create New User with Role</strong></span>
					</td>
					<td class="mo_saml_role_table_data mosaml-padding-top-bottom-1-rem">
						<select name="mo_saml_default_role_new" id="mo_saml_default_role_new" class="mo-saml-select-width-35" 
							<?php 
								echo esc_attr( $disable_new_user_role_dropdown );
							?>>
							<option value="none">None</option>
							<?php foreach ( $wp_roles_names as $role_slug => $role_name ) : ?>
								<option value="<?php echo esc_attr( $role_slug ); ?>" 
										<?php selected( $default_role_settings_data->default_role_new ?? $wp_default_role, $role_slug ); ?>>
									<?php echo esc_html( $role_name ); ?>
								</option>
							<?php endforeach; ?>
						</select><br>
						<i>Select Default Role to assign New users.</i>
					</td>
				</tr>
			</tbody>
		</table>
		<table class="mosaml-table-width">
			<tbody>
				<tr>
					<td colspan="2" class="mo_saml_role_mapping_table">
						<label class="switch">
							<input type="checkbox" name="mo_saml_update_existing_user_with_role" id="mo_saml_update_existing_user_with_role" value="checked" 
								<?php echo esc_attr( $existing_user_role_toggle_value ); ?>
	 	 						<?php echo esc_attr( $existing_user_role_toggle_disabled ); ?>
							>
							<span class="slider round"></span>
						</label>
						<span class="mo-saml-toggle-label"><strong>Update Existing User with Role</strong></span><br><br>
					</td>
					<td class="mo_saml_role_table_data">
						<select name="mo_saml_default_role_existing" id="mo_saml_default_role_existing" 
								class="mo-saml-select-width-35" 
							<?php 
								echo esc_attr( $disable_existing_user_role_dropdown );
							?>>
							<option value="none">None</option>
							<?php foreach ( $wp_roles_names as $role_slug => $role_name ) : ?>
								<option value="<?php echo esc_attr( $role_slug ); ?>" 
										<?php selected( $default_role_settings_data->default_role_existing ?? $wp_default_role, $role_slug ); ?>>
									<?php echo esc_html( $role_name ); ?>
								</option>
							<?php endforeach; ?>
						</select><br>
						<i>Select Default Role to assign Existing users.</i>
					</td>
				</tr>
			</tbody>
		</table>
	</div>
	
	<div class="mosaml-tab-content-section">
		<?php Feature_Control::start_feature_lock_container( 3 ); ?>
		<table class=" mosaml-table-width">
			<tbody>
				<tr>
					<td colspan="2" class="mo_saml_role_mapping_table">
						<strong>Apply all role mapping settings to WP admin users</strong>
					</td>
					<td class="mo_saml_role_table_data">
						<label class="switch">
							<input type="checkbox" name="mo_saml_apply_role_to_admin" id="mo_saml_apply_role_to_admin" <?php echo esc_attr( $disable_due_to_no_idp ); ?> value="checked" <?php echo esc_html( $default_role_settings_data->apply_role_mapping_to_admin ); ?>>
							<span class="slider round"></span>
						</label>
					</td>
				</tr>
			</tbody>
		</table>
		<?php Feature_Control::end_feature_lock_container( 3 ); ?>
	</div>

	<div class="mo-saml-form-submit-container">
		<br><input type="submit" name="submit" value="Save" class="button button-primary button-large mo-saml-submit-button-width" <?php echo esc_attr( $disable_due_to_no_idp ); ?> >
	</div>
</form>

