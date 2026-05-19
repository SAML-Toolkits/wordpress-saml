<?php
/**
 * Plugin sidebar UI handler.
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
use MOSAML\SRC\Constant\Constants;
use MOSAML\SRC\Utils\Feature_Control;

/**
 * Class Plugin_Sidebar_UI_Handler
 *
 * Handles the rendering of the sidebar UI in the admin menu page.
 */
class Plugin_Sidebar_UI_Handler implements Tab_UI_Handler_Interface {

	/**
	 * Render the sidebar UI.
	 *
	 * @return void
	 */
	public function render_ui() {
		$disabled                = Utility::disable_forms_if_no_idps_configured_bool();
		$disable_due_to_no_idp   = Utility::disable_forms_if_no_idps_configured();
		$disabled_due_to_license = Utility::mo_saml_get_disabled_attribute( ! Feature_Control::free_or_license_specific_feature_enabled() );
		$keep_settings_intact    = get_option( Constants::KEEP_SETTINGS_OPTION_NAME );
		$show_support_form       = true;
		$current_tab             = Utility::sanitize_get_data( 'tab' );

		if ( 'attribute_role_mapping' === $current_tab ) {
			$configured_idps_id = DB_Utils::get_configured_idps_details( 'idp_id', false, false );
			$is_enterprise      = 4 === MOSAML_VERSION;
			$selected_idp_id    = Utility::get_selected_idp_id_from_url( $is_enterprise, $configured_idps_id );
			if ( ! empty( $selected_idp_id ) ) {
				$idp_details = Utility::get_handler_object( 'sp_setup_data', true, 'admin' )->get_data(
					array(
						'environment_id' => DB_Utils::get_environment_details( 'id', false ),
						'idp_id'         => $selected_idp_id,
					),
					true
				);
				if ( ! empty( $idp_details ) && property_exists( $idp_details, 'test_config_attributes' ) && ! empty( $idp_details->test_config_attributes ) ) {
					$show_support_form = false;
					require_once Plugin_Files_Constants::TEMPLATE_TEST_CONFIG_ATTRIBUTE_TABLE;
				}
			}
		}

		if ( $show_support_form ) {
			$support_form_ui_handler = Utility::get_handler_object( 'support_form_ui', false, 'ui' );
			$support_form_ui_handler->render_ui();
		}

		if ( 'account_settings' === $current_tab ) {
			require_once Plugin_Files_Constants::TEMPLATE_BACKUP_SETTINGS_ON_UPGRADE;
		} elseif ( DB_Utils::all_tables_exist() ) {
				require_once Plugin_Files_Constants::TEMPLATE_KEEP_SETTING_INTACT;
		}
	}
}
