<?php
/**
 * Debug Logger Data Handler.
 *
 * @package miniorange-saml-20-single-sign-on/module/base/handler/admin
 */

namespace MOSAML\Module\Base\Handler\Admin;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\SRC\Interfaces\Form_Data_Handler_Interface;
use MOSAML\SRC\Utils\Utility;
use MOSAML\SRC\Utils\DB_Utils;
use MOSAML\SRC\Classes\Debug_Logger;
use MOSAML\SRC\Utils\Error_Success_Message;

/**
 * Debug Logger Data Handler.
 */
class Debug_Logger_Data_Handler implements Form_Data_Handler_Interface {

	/**
	 * Validate and save the data.
	 *
	 * @return void
	 */
	public function validate_and_save_data() {
		if ( Utility::sanitize_post_data( 'clear_debug_logs' ) ) {
			Debug_Logger::clear_debug_logs();
			Error_Success_Message::show_admin_notice( 'Successfully cleared log files.', 'SUCCESS' );
			return;
		}

		if ( Utility::sanitize_post_data( 'download_debug_logs' ) ) {
			Debug_Logger::download_debug_logs();
			return;
		}

		if ( Utility::sanitize_post_data( 'delete_debug_log_files' ) ) {
			Debug_Logger::delete_debug_log_files();
			Error_Success_Message::show_admin_notice( 'Successfully deleted log files.', 'SUCCESS' );
			return;
		}

		if ( 'checked' === Utility::sanitize_post_data( 'mo_saml_enable_debug_logs' ) ) {
			$result = Debug_Logger::enable_debug_log();
		} else {
			$result = Debug_Logger::disable_debug_log();
			if ( $result ) {
				$mosaml_debug_logger_disabled = 'mosaml_debug_logger_disabled';
				$GLOBALS[ $mosaml_debug_logger_disabled ] = true;
				Error_Success_Message::show_admin_notice( 'Debug Logs have been disabled successfully.', 'SUCCESS' );
				return;
			}
		}

		if ( $result ) {
			sleep( (int) 2 );
			wp_safe_redirect( Utility::get_current_page_url() );
			exit();
		}
	}

	/**
	 * Get the data.
	 *
	 * @param array $where The where clause to filter the data.
	 * @return object The data.
	 */
	public function get_data( $where = array() ) {
		return $this;
	}
}
