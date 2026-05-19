<?php
/**
 * Debug Logger UI Handler.
 *
 * @package miniorange-saml-20-single-sign-on
 */

namespace MOSAML\SRC\Handler\UI;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\SRC\Interfaces\Tab_UI_Handler_Interface;
use MOSAML\SRC\Constant\Constants;
use MOSAML\SRC\Constant\Plugin_Files_Constants;
use MOSAML\SRC\Utils\Feature_Control;

/**
 * Debug Logger UI Handler.
 */
class Debug_Logger_UI_Handler implements Tab_UI_Handler_Interface {

	/**
	 * Render the UI.
	 *
	 * @return void
	 */
	public function render_ui() {
		$is_license_valid  = Feature_Control::check_is_license_valid();
		$debug_log_enabled = defined( Constants::DEBUG_LOG_CONSTANT ) && true === constant( Constants::DEBUG_LOG_CONSTANT ) ? 'checked' : '';
		$disabled          = ! defined( Constants::DEBUG_LOG_CONSTANT ) || true !== constant( Constants::DEBUG_LOG_CONSTANT ) || ! $is_license_valid ? 'disabled' : '';
		$delete_disabled   = ( defined( Constants::DEBUG_LOG_CONSTANT ) && true === constant( Constants::DEBUG_LOG_CONSTANT ) ) || ! $is_license_valid ? 'disabled' : '';
		$license_disabled  = ! $is_license_valid ? 'disabled' : '';
		
		$mosaml_debug_logger_disabled = 'mosaml_debug_logger_disabled';
		if ( ! empty( $GLOBALS[ $mosaml_debug_logger_disabled ] ) ) {
			$debug_log_enabled = '';
			$disabled          = 'disabled';
			$delete_disabled   = ! $is_license_valid ? 'disabled' : '';
		}

		require_once Plugin_Files_Constants::TEMPLATE_DEBUG_LOGGER;
	}
}
