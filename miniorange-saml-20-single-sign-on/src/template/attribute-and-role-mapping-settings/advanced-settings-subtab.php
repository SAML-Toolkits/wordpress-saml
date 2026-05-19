<?php
/**
 * Advanced Settings Subtab Template
 *
 * This template renders the advanced settings form using data from the passed data object.
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

<form name="mosaml_role_mapping_advanced_settings_form" method="post" action="<?php echo esc_url( $role_mapping_advanced_settings_subtab_url ); ?>" class="mo_saml_attribute_role_table">
	<?php wp_nonce_field( 'mosaml_role_mapping_advanced_settings_form' ); ?>
	<input type="hidden" name="option" value="mosaml_role_mapping_advanced_settings_form">
	<input type="hidden" name="selected_idp_name" value="<?php echo esc_attr( $selected_idp ); ?>">
	<?php Feature_Control::check_plugin_state(); ?>
	
	[ <a target="_blank" href="<?php echo esc_url( Constants::ROLE_MAPPING_ADVANCED_SETTINGS_DOC_URL ); ?>">Click here</a> to know how this is useful. ]<br><br>

	<div class="mosaml-tab-content-section mosaml-no-border-bottom">
		<?php Feature_Control::start_feature_lock_container( 3 ); ?>
		<table class="mosaml-table-width">
			<tbody>
				<tr>
					<td colspan="2" class="mo_saml_role_mapping_table">
						<strong>Do not create new users</strong>
					</td>
					<td class="mo_saml_role_table_data">
						<label class="switch">
							<input type="checkbox" name="mo_saml_dont_create_new_users" value="checked" 
							<?php
							echo esc_html( $data->do_not_create_new_users );
							echo esc_attr( $disable_due_to_no_idp );
							?>
							>
							<span class="slider round"></span>
						</label>
					</td>
				</tr>
				<tr>
					<td colspan="2" class="mo_saml_role_mapping_table">
						<strong>Do not update existing user's roles</strong>
					</td>
					<td class="mo_saml_role_table_data">
						<label class="switch">
							<input type="checkbox" name="mo_saml_do_not_update_existing_user" id="mo_saml_do_not_update_existing_user" value="checked" 
							<?php
							echo esc_html( $data->do_not_update_existing_user_roles );
							echo esc_attr( $disable_due_to_no_idp );
							?>
							>
							<span class="slider round"></span>
						</label>
					</td>
				</tr>
			</tbody>
		</table>
		<?php Feature_Control::end_feature_lock_container( 3 ); ?>
	</div>
	
	<div class="mosaml-tab-content-section mosaml-no-border-bottom">
		<?php Feature_Control::start_feature_lock_container( 3 ); ?>
		<table class="mosaml-table-width">
			<tbody>
				<tr>
					<td colspan="2" class="mo_saml_role_mapping_table">
						<strong>Whitelist existing user's roles</strong>
					</td>
					<td class="mo_saml_role_table_data">
						<label class="switch">
							<input type="checkbox" id="mo_saml_whitelist_existing_users_roles" name="mo_saml_whitelist_existing_users_roles"  value="checked" <?php echo esc_html( $data->whitelist_existing_users_roles ); ?> <?php disabled( ( ! empty( $data->do_not_update_existing_user_roles ) || ! empty( $disabled ) ), true ); ?>>
							<span class="slider round"></span>
						</label>
					</td>
				</tr>
				<tr>
					<td colspan="2" class="mo_saml_role_mapping_table">
						<strong>Whitelisted Roles</strong> (Roles that should not be updated)
					</td>
					<td class="mo_saml_role_table_data">
						<div class="mo-saml-whitelist-roles-multiselect-wrapper">
							<?php
							$white_listed_roles = $data->whitelisted_roles;
							if ( ! $white_listed_roles ) {
								$white_listed_roles = $available_roles;
							}
							$row_white_listed_roles = implode( ';', $white_listed_roles );
							?>
							<input type="text" id="multiselect_search" class="mo-saml-whitelist-roles-search-box mo-saml-whitelist-roles-search-box-width" placeholder="Search roles" value="<?php echo esc_attr( $row_white_listed_roles ); ?>" <?php disabled( ( ! empty( $data->do_not_update_existing_user_roles ) || ! empty( $disabled ) ), true ); ?>>
							<div class="mo-saml-whitelist-roles-multiselect-dropdown" id="mo_saml_whitelist_roles_multiselect_dropdown">
								<div class="mo-saml-whitelist-roles-multiselect-header">
									<input type="checkbox" id="select_all_checkbox" <?php checked( is_countable( $white_listed_roles ) && is_countable( $available_roles ) && count( $white_listed_roles ) === count( $available_roles ), true ); ?>> Select All
								</div>
								<div class="multiselect-options">
									<?php if ( ! empty( $available_roles ) ) : ?>
										<?php foreach ( $available_roles as $role_slug => $role_name ) : ?>
											<div class="dropdown-item">
												<input type="checkbox" name="mo_saml_whitelisted_roles[<?php echo esc_attr( $role_slug ); ?>]" value="<?php echo esc_attr( $role_name ); ?>" <?php checked( isset( $white_listed_roles[ $role_slug ] ), true ); ?>> <?php echo esc_html( $role_name ); ?>
											</div>
										<?php endforeach; ?>
									<?php endif; ?>
								</div>
							</div>
						</div>
					</td>
				</tr>
			</tbody>
		</table>
		<?php Feature_Control::end_feature_lock_container( 3 ); ?>
	</div>

	<div class="mosaml-tab-content-section mosaml-no-border-bottom">
		<?php Feature_Control::start_feature_lock_container( 3 ); ?>
		<table class="mosaml-table-width">
			<tbody>
				<tr>
					<td colspan="2" class="mo_saml_role_mapping_table">
						<strong>Allow/Deny user login based on IDP Attribute values</strong>
					</td>
					<td class="mo_saml_role_table_data">
						<label class="switch">
							<input type="checkbox" name="mo_saml_allow_deny_idp_attribute_toggle" id="mo_saml_allow_deny_idp_attribute_toggle" value="checked" 
							<?php
							echo esc_html( $data->allow_deny_idp_attribute_toggle );
							echo esc_attr( $disable_due_to_no_idp );
							?>
							>
							<span class="slider round"></span>
						</label>
					</td>
				</tr>
				<tr>
					<td colspan="2" class="mo_saml_role_mapping_table">
						<strong>IDP Attribute Name</strong>
					</td>
					<td class="mo_saml_role_table_data">
						<?php
						$disabled_org    = $disabled;
						$field_name      = 'attribute_restriction_attr_name';
						$field_label     = 'Restriction Attribute';
						$field_id_name   = 'mo_saml_attribute_restriction_attr_name';
						$current_value   = isset( $data->attribute_restriction_group ) ? $data->attribute_restriction_group : '';
						$test_attributes = $test_config_attributes;
						$is_required     = true;
						$disabled        = ! empty( $data->allow_deny_idp_attribute_toggle ) && empty( $disabled ) ? null : true;
						require Plugin_Files_Constants::ATTRIBUTE_DROPDOWN;
						$disabled = $disabled_org;
						?>
					</td>
				</tr>
				<tr>
					<td colspan="2" class="mo_saml_role_mapping_table">
						<strong>IDP Attribute Value</strong>
					</td>
					<td class="mo_saml_role_table_data">
						<input type="text" name="mo_saml_attribute_restriction_attr_value" id="mo_saml_attribute_restriction_attr_value" placeholder="Semicolon(;) separated values" class="mo-saml-attr-input-width" value="<?php echo esc_attr( $data->attribute_restriction_value ); ?>" <?php disabled( ! empty( $data->attribute_restriction_group ) && empty( $disabled ) ? '' : true ); ?> required="">
						<br>
						<div class="mo-saml-padding-top-3px">
							<input type="radio" name="mo_saml_allow_deny_idp_attribute" id="attribute_allowed" value="allow" 
							<?php
							checked( $data->allow_deny_idp_attribute, 'allow' );
							disabled( ! empty( $data->attribute_restriction_group ) && empty( $disabled ) ? '' : true );
							?>
							required>Allow
							<input type="radio" name="mo_saml_allow_deny_idp_attribute" id="attribute_denied" value="deny" 
							<?php
							checked( $data->allow_deny_idp_attribute, 'deny' );
							disabled( ! empty( $data->attribute_restriction_group ) && empty( $disabled ) ? '' : true );
							?>
							>Deny
						</div>
					</td>
				</tr>
			</tbody>
		</table>
		<?php Feature_Control::end_feature_lock_container( 3 ); ?>
	</div>

	<div class="mosaml-tab-content-section mosaml-no-border-bottom">
		<?php Feature_Control::start_feature_lock_container( 3 ); ?>
		<table class="mosaml-table-width">
			<tbody>
				<tr>
					<td colspan="2" class="mo_saml_role_mapping_table">
						<strong>Allow/Deny user login based on email domain</strong>
					</td>
					<td class="mo_saml_role_table_data">
						<label class="switch">
							<input type="checkbox" name="mo_saml_allow_deny_user_domain_toggle" id="mo_saml_allow_deny_user_domain_toggle" value="checked" 
							<?php
							echo esc_html( $data->allow_deny_user_domain_toggle );
							echo esc_attr( $disable_due_to_no_idp );
							?>
							>
							<span class="slider round"></span>
						</label>
					</td>
				</tr>
				<tr>
					<td colspan="2" class="mo_saml_role_mapping_table">
						<strong>Email Domains</strong>
					</td>
					<td class="mo_saml_role_table_data">
						<input type="text" name="mo_saml_allow_deny_user_domain_value" pattern="^\s*(?:[a-zA-Z0-9]+(?:-[a-zA-Z0-9]+)*(\.[a-zA-Z0-9]+(?:-[a-zA-Z0-9]+)*)+\s*;\s*)*[a-zA-Z0-9]+(?:-[a-zA-Z0-9]+)*(\.[a-zA-Z0-9]+(?:-[a-zA-Z0-9]+)*)+\s*;?\s*$" id="mo_saml_allow_deny_user_domain_value" placeholder="Semicolon(;) separated domains" class="mo-saml-attr-input-width" value="<?php echo esc_attr( isset( $data->allow_deny_user_domain_value ) ? $data->allow_deny_user_domain_value : '' ); ?>" <?php disabled( ( ! empty( $data->allow_deny_user_domain_toggle ) && empty( $disabled ) ) ? '' : true ); ?> required="">
						<br>
						<div class="mo-saml-padding-top-3px">
							<input type="radio" name="mo_saml_allow_deny_user_domain" id="domain_allowed" value="allow" 
							<?php
							checked( $data->allow_deny_user_domain_type, 'allow' );
							disabled( ( ! empty( $data->allow_deny_user_domain_value ) && empty( $disabled ) ) ? '' : true );
							?>
							required>Allow
							<input type="radio" name="mo_saml_allow_deny_user_domain" id="domain_denied" value="deny" 
							<?php
							checked( $data->allow_deny_user_domain_type, 'deny' );
							disabled( ( ! empty( $data->allow_deny_user_domain_value ) && empty( $disabled ) ) ? '' : true );
							?>
							>Deny
						</div>
					</td>
				</tr>
			</tbody>
		</table>
		<?php Feature_Control::end_feature_lock_container( 3 ); ?>
	</div>

	<div class="mosaml-tab-content-section">
		<?php Feature_Control::start_feature_lock_container( 3 ); ?>
		<table class="mosaml-table-width">
			<tbody>
				<tr>
					<td colspan="2" class="mo_saml_role_mapping_table">
						<strong>Enable Regex for Role Mapping</strong>
					</td>
					<td class="mo_saml_role_table_data">
						<label class="switch">
							<input type="checkbox" name="mo_saml_enable_regex_for_role_mapping" id="mo_saml_enable_regex_for_role_mapping" value="checked" 
							<?php
							echo esc_html( $data->enable_regex_for_role_mapping );
							echo esc_attr( $disable_due_to_no_idp );
							?>
							>
							<span class="slider round"></span>
						</label>
					</td>
				</tr>
			</tbody>
		</table>
		<?php Feature_Control::end_feature_lock_container( 3 ); ?>
	</div>

	<div class="mo-saml-form-submit-container">
		<br><input type="submit" name="submit" value="Save" class="button button-primary button-large mo-saml-submit-button-width" 
		<?php
		echo esc_attr( Feature_Control::get_disabled_attribute( 3 ) );
		echo esc_attr( $disable_due_to_no_idp );
		?>
		>
	</div>
</form>
