<?php
/**
 * This file contains a handler to process custom exception and pass it to be displayed.
 *
 * @package miniorange-saml-20-single-sign-on/handler
 */

namespace MOSAML\SRC\Handler;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\SRC\Constant\Error_Codes_Enums;
use MOSAML\SRC\Constant\Plugin_Files_Constants;
use MOSAML\SRC\Utils\Error_Success_Message;
use MOSAML\SRC\Utils\Utility;
use MOSAML\SRC\Constant\Constants;

/**
 * Handler to process custom exception and pass it to be displayed.
 */
class Exception_Handler {

	/**
	 * Used to display exceptions, if the exception has a non 0 code this function fetches the error code defined by plugin.
	 *
	 * @param Exception $exception Exception object.
	 * @param bool      $is_notice Optional. Determines if the thrown exception should be shown as an admin notice. Default false.
	 * @param array     $details Optional. Additional details to be displayed. Default empty array.
	 * @return void
	 */
	public static function throw_exception( $exception, $is_notice = false, $details = array() ) {
		$code       = $exception->getCode();
		$error_code = 'WPSAMLERR';
		if ( 0 !== $code ) {
			if ( $code < 10 ) {
				$error_code .= '00' . $code;
			} else {
				$error_code .= '0' . $code;
			}
			if ( ! empty( Error_Codes_Enums::$error_codes[ $error_code ] ) ) {
				if ( Utility::is_test_configuration_request() ) {
					$relay_state = Utility::sanitize_relay_state_request();
					if ( 'testSSOLogin' === $relay_state && ( ! is_user_logged_in() || ! current_user_can( 'manage_options' ) ) ) {
						$end_user_test      = true;
						$idp_attributes     = array();
						$show_error_message = false;
						require_once Plugin_Files_Constants::TEMPLATE_TEST_CONFIG;
						exit;
					} else {
						$transient_key = wp_generate_uuid4();
						set_transient( $transient_key, $exception->getMessage(), 60 );
						wp_safe_redirect(
							add_query_arg(
								array(
									'page'   => 'mo_saml_settings',
									'option' => 'mosaml_error_' . $error_code,
									'key'    => $transient_key,
								),
								admin_url( 'admin.php' )
							)
						);
						exit;
					}
				} elseif ( $is_notice ) {
					self::display_error_notice_to_admin( Error_Codes_Enums::$error_codes[ $error_code ] );
				} else {
					self::display_error_code_message( Error_Codes_Enums::$error_codes[ $error_code ] );
				}
			}
		}
	}

	/**
	 * Displays the error message to admin users along with the provided error code.
	 *
	 * @param array $error_code An array containing the error code details: code, fix, cause and description.
	 * @return void
	 */
	public static function display_error_notice_to_admin( $error_code ) {
		// TODO: Add error message to the database.
		update_option(
			Constants::ADMIN_NOTICE_MESSAGE_OPTION_NAME,
			'<b>[' . esc_attr( $error_code['code'] ) . ']</b> ' . esc_attr( $error_code['cause'] ) . '</br><b>Fix:</b> ' . esc_attr( $error_code['fix'] )
		);
		Error_Success_Message::show_error_message();
	}

	/**
	 * Displays the error message to end users along with the provided error code.
	 *
	 * @param array $error_code An array containing the error code details: code, fix, cause and description.
	 * @return void
	 */
	public static function display_error_code_message( $error_code ) {
		wp_die( '<b>[' . esc_attr( $error_code['code'] ) . ']</b> ' . esc_attr( Error_Codes_Enums::ERROR_MESSAGE ), esc_attr( $error_code['code'] ) . ' ' . esc_attr( $error_code['cause'] ) );
	}
}
