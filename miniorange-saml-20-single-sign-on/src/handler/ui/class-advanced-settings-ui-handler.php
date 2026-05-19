<?php
/**
 * Advanced Settings UI Handler.
 *
 * @package miniorange-saml-20-single-sign-on
 */

namespace MOSAML\SRC\Handler\UI;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\SRC\Interfaces\Tab_UI_Handler_Interface;
use MOSAML\SRC\Constant\Plugin_Files_Constants;
use MOSAML\SRC\Utils\Utility;
use MOSAML\SRC\Utils\DB_Utils;
use MOSAML\SRC\Utils\Feature_Control;
use MOSAML\SRC\Constant\Constants;

/**
 * Class Advanced_Settings_UI_Handler
 *
 * Handles the rendering of the Advanced Settings tab UI.
 */
class Advanced_Settings_UI_Handler implements Tab_UI_Handler_Interface {

	/**
	 * Render the UI.
	 *
	 * @return void
	 */
	public function render_ui() {
		$disabled                = Utility::disable_forms_if_no_idps_configured_bool();
		$disable_due_to_no_idp   = Utility::disable_forms_if_no_idps_configured();
		$disabled_due_to_license = Utility::mo_saml_get_disabled_attribute( ! Feature_Control::free_or_license_specific_feature_enabled() );

		$is_enterprise      = 'ENTERPRISE' === Constants::VERSION_HIERARCHY[ MOSAML_VERSION ];
		$configured_idps_id = DB_Utils::get_configured_idps_details( 'idp_id', false, false );
		$configured_idps    = DB_Utils::get_configured_idps_details( '', false, true );

		$selected_idp_id      = Utility::get_selected_idp_id_from_url( $is_enterprise, $configured_idps_id );
		$selected_idp_details = DB_Utils::get_records(
			Constants::DATABASE_TABLE_NAMES['idp_details'],
			array(
				'idp_id'         => $selected_idp_id,
				'environment_id' => DB_Utils::get_environment_details( 'id', false ),
			),
			true
		);

		$selected_idp      = ! empty( $selected_idp_details ) ? $selected_idp_details->id : '';
		$selected_idp_name = ! empty( $selected_idp_details ) ? $selected_idp_details->idp_name : '';
		$subsite_id         = Utility::get_subsite_id_for_environment();
		$logout_all_sessions_data = Utility::get_handler_object( 'logout_all_sessions_data', true, 'admin' )->get_data(
			array(
				'option_name' => 'saml_force_complete_logout',
				'idp_id'      => $selected_idp,
				'subsite_id'  => $subsite_id,
			)
		);
		if ( $logout_all_sessions_data ) {
			$saml_force_complete_logout = $logout_all_sessions_data->saml_force_complete_logout;
		} else {
			$saml_force_complete_logout = 'unchecked';
		}

		$environment_id      = DB_Utils::get_environment_details( 'id', false );
		$default_idp_id      = DB_Utils::get_default_inserted_idp_details( 'id', $environment_id );
		$custom_message_data = Utility::get_handler_object( 'custom_messages_data', true, 'admin' )->get_data(
			array(
				'option_name' => array( 'account_creation_disabled_msg', 'restricted_domain_error_msg' ),
				'idp_id'      => $default_idp_id,
				'subsite_id'  => $subsite_id,
			)
		);
		$sso_user_data       = Utility::get_handler_object( 'sso_user_data', true, 'admin' )->get_data(
			array(
				'option_name' => 'sso_show_user',
				'idp_id'      => $default_idp_id,
				'subsite_id'  => $subsite_id,
			)
		);
		require_once Plugin_Files_Constants::TEMPLATE_ADVANCED_SETTING;
	}
}
