<?php
/**
 * Manage Multiple Environments UI Handler
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
use MOSAML\SRC\Template\Environment_List_Table;
use MOSAML\SRC\Utils\DB_Utils;
use MOSAML\SRC\Constant\Constants;

/**
 * Manage Multiple Environments UI Handler
 */
class Manage_Multiple_Environments_UI_Handler implements Tab_UI_Handler_Interface {

	/**
	 * Render the UI.
	 *
	 * @return void
	 */
	public function render_ui() {
		$enable_multiple_environments = get_option( Constants::ENABLE_MULTIPLE_ENVIRONMENTS_OPTION_NAME );
		if ( MOSAML_VERSION < 4 ) {
			$enable_multiple_environments = '';
		}
		$disable_multiple_environment_option = 'checked' === $enable_multiple_environments ? '' : 'disabled';

		$current_envinmemt_details = DB_Utils::get_environment_details( '' );

		$plugin_config_url = admin_url( 'admin.php?page=mo_saml_settings' );

		$environments = Utility::get_handler_object( 'multiple_environments_data', true, 'admin' )->get_data();

		$environment_list_table = new Environment_List_Table( $environments, $current_envinmemt_details, $disable_multiple_environment_option );
		$environment_list_table->prepare_items();
		require_once Plugin_Files_Constants::TEMPLATE_MANAGE_MULTIPLE_ENVIRONMENTS;
	}
}
