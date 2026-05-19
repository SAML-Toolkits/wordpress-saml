<?php
/**
 * Error and Success Message Handler.
 *
 * @package miniorange-saml-20-single-sign-on/utils
 */

namespace MOSAML\SRC\Utils;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\SRC\Constant\Error_Codes_Enums;
use MOSAML\SRC\Constant\Constants;
use MOSAML\SRC\Constant\Plugin_Files_Constants;

/**
 * Handles the methods to show the error messages.
 *
 * This class provides static methods to display error messages to administrators
 * and end users in different contexts (admin notices, wp_die messages, test configuration).
 *
 * @package MOSAML\SRC\Utils
 * @since 1.0
 */
class Error_Success_Message {

	/**
	 * Displays the error message to admins via admin notice.
	 *
	 * @param array $error_code An array containing the error code details: code, fix, cause and description.
	 * @return void
	 */
	public static function display_error_notice_to_admin( $error_code ) {
		update_option(
			Constants::ADMIN_NOTICE_MESSAGE_OPTION_NAME,
			'<b>[' . esc_attr( $error_code['code'] ) . ']</b> ' . esc_attr( $error_code['cause'] ) . '</br><b>Fix:</b> ' . esc_attr( $error_code['fix'] )
		);
		self::show_error_message();
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

	/**
	 * Function to show error message.
	 *
	 * @return void
	 */
	public static function error_message() {
		$class   = 'error';
		$message = get_option( Constants::ADMIN_NOTICE_MESSAGE_OPTION_NAME );
		echo "<div class='" . esc_html( $class ) . "'> <p>" . wp_kses_post( $message ) . '</p></div>';
	}

	/**
	 * Function to show success message.
	 *
	 * @return void
	 */
	public static function success_message() {
		$class   = 'updated';
		$message = get_option( Constants::ADMIN_NOTICE_MESSAGE_OPTION_NAME );
		echo "<div class='" . esc_html( $class ) . "'> <p>" . wp_kses_post( $message ) . '</p></div>';
	}

	/**
	 * Function to show error message via admin notices.
	 *
	 * @return void
	 */
	public static function show_error_message() {
		remove_action(
			'admin_notices',
			array(
				'MOSAML\SRC\Utils\Error_Success_Message',
				'success_message',
			)
		);
		add_action(
			'admin_notices',
			array(
				'MOSAML\SRC\Utils\Error_Success_Message',
				'error_message',
			)
		);
	}

	/**
	 * Function to show success message via admin notices.
	 *
	 * @return void
	 */
	public static function show_success_message() {
		remove_action(
			'admin_notices',
			array(
				'MOSAML\SRC\Utils\Error_Success_Message',
				'error_message',
			)
		);
		add_action(
			'admin_notices',
			array(
				'MOSAML\SRC\Utils\Error_Success_Message',
				'success_message',
			)
		);
	}

	/**
	 * Function to show test config error message.
	 *
	 * @param array $error_code An array containing the error code details: code, fix, cause and description.
	 * @param array $details An array containing the details of the error to display.
	 * @return void
	 */
	public static function show_test_config_admin_error_window( $error_code, $details = array() ) {
		$show_error_message = true;
		require_once Plugin_Files_Constants::TEMPLATE_TEST_CONFIG;
		exit;
	}

	/**
	 * Function to show test config window.
	 *
	 * @param bool   $end_user_test Whether the test is for end user.
	 * @param array  $idp_attributes The IDP attributes.
	 * @param string $redirect_url The redirect URL.
	 * @param string $redirect_button_text The redirect button text.
	 * @param string $idp_id The IDP ID.
	 * @return void
	 */
	public static function show_test_config_window( $end_user_test = false, $idp_attributes = array(), $redirect_url = '', $redirect_button_text = '', $idp_id = '' ) {
		$show_error_message = false;
		require_once Plugin_Files_Constants::TEMPLATE_TEST_CONFIG;
		exit;
	}

	/**
	 * This function shows the success or error message in the admin notice.
	 *
	 * @param string $message Contains message to be displayed.
	 * @param string $status The status of the message, either 'SUCCESS' or 'ERROR'.
	 *
	 * @return void
	 */
	public static function show_admin_notice( $message, $status = 'ERROR' ) {
		update_option( Constants::ADMIN_NOTICE_MESSAGE_OPTION_NAME, $message );
		if ( 'SUCCESS' === $status ) {
			self::show_success_message();
			return;
		}

		self::show_error_message();
	}

	/**
	 * HTML fragment: SP metadata URL with target="_blank" for admin notices.
	 *
	 * @return string
	 */
	public static function get_sp_metadata_view_link_for_notice() {
		$url = site_url( Constants::METADATA_URL );
		return '<a href="' . esc_url( $url ) . '" target="_blank" rel="noopener noreferrer"><b>' . esc_html( '[ View Metadata ]' ) . '</b></a>';
	}
}
