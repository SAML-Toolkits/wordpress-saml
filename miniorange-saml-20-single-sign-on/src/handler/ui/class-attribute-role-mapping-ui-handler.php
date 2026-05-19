<?php
/**
 * Attribute Role Mapping UI Handler
 *
 * This class handles the UI for the Attribute Role Mapping tab.
 *
 * @package MOSAML
 * @since 1.0.0
 */

namespace MOSAML\SRC\Handler\UI;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\SRC\Constant\Constants;
use MOSAML\SRC\Constant\Plugin_Files_Constants;
use MOSAML\SRC\Interfaces\Tab_UI_Handler_Interface;
use MOSAML\SRC\Utils\DB_Utils;
use MOSAML\SRC\Utils\Utility;
use MOSAML\SRC\Utils\Feature_Control;

/**
 * Attribute Role Mapping UI Handler.
 */
class Attribute_Role_Mapping_UI_Handler implements Tab_UI_Handler_Interface {


	/**
	 * Renders the UI for the Attribute Mapping tab.
	 *
	 * @return void
	 */
	public function render_ui() {
		$disabled                = Utility::disable_forms_if_no_idps_configured_bool();
		$disable_due_to_no_idp   = Utility::disable_forms_if_no_idps_configured();
		$disabled_due_to_license = Utility::mo_saml_get_disabled_attribute( ! Feature_Control::free_or_license_specific_feature_enabled() );

		global $wp_roles;
		$is_enterprise      = 'ENTERPRISE' === Constants::VERSION_HIERARCHY[ MOSAML_VERSION ];
		$configured_idps_id = DB_Utils::get_configured_idps_details( 'idp_id', false, false );
		$configured_idps    = DB_Utils::get_configured_idps_details( '', false, false );

		if ( 4 === MOSAML_VERSION ) {
			$idp_count = count( $configured_idps ) - 1;
		} else {
			$idp_count = count( $configured_idps );
		}

		$active_subtab = ! empty( Utility::sanitize_get_data( 'subtab' ) ) ? Utility::sanitize_get_data( 'subtab' ) : 'attribute_mapping';

		$selected_idp_id      = Utility::get_selected_idp_id_from_url( $is_enterprise, $configured_idps_id );
		$selected_idp_details = DB_Utils::get_records(
			Constants::DATABASE_TABLE_NAMES['idp_details'],
			array(
				'idp_id'         => $selected_idp_id,
				'environment_id' => DB_Utils::get_environment_details( 'id', false ),
			),
			true
		);

		$environment_id         = DB_Utils::get_environment_details( 'id', false );
		$current_environment_id = DB_Utils::get_environment_details( 'id', true );
		$is_current_environment = $environment_id === $current_environment_id;

		$selected_idp      = ! empty( $selected_idp_details ) ? $selected_idp_details->id : '';
		$selected_idp_name = ! empty( $selected_idp_details ) ? $selected_idp_details->idp_name : '';

		$selected_subsite = Utility::get_subsite_id_for_environment( $environment_id );
		$active_tab_handler_object = Utility::get_handler_object( $active_subtab . '_data', true, 'admin' );
		$where                     = array( 'idp_id' => $selected_idp );
		if ( 'attribute_mapping' !== $active_subtab ) {
			$where['subsite_id'] = $selected_subsite;
		}
		$data                         = $active_tab_handler_object->get_data( $where );
		$available_roles              = $wp_roles->get_names();
		$wp_default_role              = get_option( 'default_role', 'subscriber' );
		$admin_url                    = admin_url( 'admin.php?page=mo_saml_settings' );
		$reset_button_name            = 'Attribute Mapping';
		$disable_reset_button_version = 2;
		if ( 'role_mapping' === $active_subtab ) {
			$reset_button_name            = 'Role Mapping';
			$disable_reset_button_version = 3;
		}
		if ( 'role_mapping_advanced_settings' === $active_subtab ) {
			$reset_button_name            = 'Advanced Settings';
			$disable_reset_button_version = 3;
		}

		$test_config_attributes = ! empty( $selected_idp_details->test_config_attributes ) ? maybe_unserialize( $selected_idp_details->test_config_attributes ) : array();
		if ( is_array( $test_config_attributes ) && ! empty( $test_config_attributes ) ) {
			$test_config_attributes = array_keys( $test_config_attributes );
		}
		$attribute_mapping_subtab_url              = add_query_arg(
			array(
				'tab'    => 'attribute_role_mapping',
				'subtab' => 'attribute_mapping',
				'idp'    => $selected_idp_id,
			),
			$admin_url
		);
		$role_mapping_subtab_url                   = add_query_arg(
			array(
				'tab'    => 'attribute_role_mapping',
				'subtab' => 'role_mapping',
				'idp'    => $selected_idp_id,
			),
			$admin_url
		);
		$role_mapping_advanced_settings_subtab_url = add_query_arg(
			array(
				'tab'    => 'attribute_role_mapping',
				'subtab' => 'role_mapping_advanced_settings',
				'idp'    => $selected_idp_id,
			),
			$admin_url
		);
		$service_provider_setup_url                = add_query_arg(
			array(
				'tab' => 'sp_setup',
			),
			$admin_url
		);
		require_once Plugin_Files_Constants::TEMPLATE_ATTRIBUTE_AND_ROLE_MAPPING_TAB;

		switch ( $active_subtab ) {
			case 'attribute_mapping':
				require_once Plugin_Files_Constants::TEMPLATE_ATTRIBUTE_MAPPING_SUBTAB;
				break;
			case 'role_mapping':
				$default_role_settings_data = Utility::get_handler_object( 'role_assignment_settings_data', true, 'admin' )->get_data(
					array(
						'idp_id'     => $selected_idp,
						'subsite_id' => $selected_subsite,
					)
				);

				if ( MOSAML_VERSION <= 2 ) {
					$new_user_role_toggle_value     = 'checked';
					$new_user_role_toggle_disabled  = 'disabled';
					$disable_new_user_role_dropdown = ( $disabled ) ? 'disabled' : '';
				} else {
					$new_user_role_toggle_value     = ! empty( $default_role_settings_data->create_new_user ) ? 'checked' : '';
					$new_user_role_toggle_disabled  = $disable_due_to_no_idp;
					$disable_new_user_role_dropdown = ( empty( $new_user_role_toggle_value ) || $disabled ) ? 'disabled' : '';
				}

				if ( 1 === MOSAML_VERSION ) {
					$existing_user_role_toggle_value     = '';
					$existing_user_role_toggle_disabled  = 'disabled';
					$disable_existing_user_role_dropdown = 'disabled';
				} else {
					$existing_user_role_toggle_value     = ! empty( $default_role_settings_data->update_existing_user ) ? 'checked' : '';
					$existing_user_role_toggle_disabled  = $disable_due_to_no_idp;
					$disable_existing_user_role_dropdown = ( empty( $existing_user_role_toggle_value ) || $disabled ) ? 'disabled' : '';
				}

				$field_name      = 'group_attribute_name';
				$field_label     = 'Group/Role';
				$current_value   = ! empty( $default_role_settings_data->group_attribute_name ) ? $default_role_settings_data->group_attribute_name : '';
				$test_attributes = $test_config_attributes;
				$is_required     = false;
				$placeholder     = 'Enter attribute name for group';
				$field_id_name   = 'mo_saml_rm_group_name';

				$wp_roles_obj   = wp_roles();
				$wp_roles_names = $wp_roles_obj->get_names();

				$role_mapping_values = ! empty( $data->role_mapping_values ) && is_array( $data->role_mapping_values ) ? $data->role_mapping_values : array();

				require_once Plugin_Files_Constants::TEMPLATE_ROLE_MAPPING_SUBTAB;
				break;
			case 'role_mapping_advanced_settings':
				require_once Plugin_Files_Constants::TEMPLATE_ADVANCED_SETTINGS_SUBTAB;
				break;
			default:
				require_once Plugin_Files_Constants::TEMPLATE_ATTRIBUTE_MAPPING_SUBTAB;
				break;
		}
	}
}
