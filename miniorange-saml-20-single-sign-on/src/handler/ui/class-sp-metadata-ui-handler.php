<?php
/**
 * SP Metadata UI Handler
 *
 * This file contains the SP_Metadata_UI_Handler class which handles the rendering
 * of the SP Metadata tab UI.
 *
 * @package MOSAML
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

/**
 * SP Metadata UI Handler
 *
 * Handles the rendering of the SP Metadata tab UI by loading the required data
 * and including the template file.
 */
class SP_Metadata_UI_Handler implements Tab_UI_Handler_Interface {

	/**
	 * Render the SP Metadata UI.
	 *
	 * Loads SP endpoints, organization details, and certificate data,
	 * then renders the SP metadata tab template.
	 *
	 * @return void
	 */
	public function render_ui() {
		$current_environment_id  = DB_Utils::get_environment_details( 'id', true );
		$selected_environment_id = DB_Utils::get_environment_details( 'id', false );
		$sp_endpoints            = Utility::get_handler_object( 'sp_endpoints_data', true, 'Admin' )->get_data( array( 'environment_id' => $selected_environment_id ) );
		$sp_organization_details = Utility::get_handler_object( 'sp_organization_data', true, 'Admin' )->get_data( array( 'environment_id' => $selected_environment_id ) );

		$disabled                = Utility::disable_forms_if_no_idps_configured_bool();
		$disable_due_to_no_idp   = Utility::disable_forms_if_no_idps_configured();
		$disabled_due_to_license = Utility::mo_saml_get_disabled_attribute( ! Feature_Control::free_or_license_specific_feature_enabled() );

		$show_point_a = false;
		$point_b      = 'a';
		$point_c      = 'b';
		if ( $current_environment_id === $selected_environment_id ) {
			$show_point_a = true;
			$point_b      = 'b';
			$point_c      = 'c';
		}
		require_once Plugin_Files_Constants::TEMPLATE_SP_METADATA_TAB;
	}
}
