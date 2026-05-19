<?php
/**
 * Feedback Form Handler.
 *
 * @package miniorange-saml-20-single-sign-on
 */

namespace MOSAML\SRC\Handler\UI;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\SRC\Classes\Mo_Customer;
use MOSAML\SRC\Constant\Plugin_Files_Constants;
use MOSAML\SRC\Utils\Utility;
use MOSAML\SRC\Utils\Error_Success_Message;

/**
 * Class to handle feedback form display and submission.
 */
class Feedback_Form_Handler {
	/**
	 * Handle feedback form submission.
	 *
	 * @return void
	 */
	public function handle_feedback_submission() {
		$email   = Utility::sanitize_post_data( 'query_mail' );
		$rate    = Utility::sanitize_post_data( 'rate' ) ? absint( Utility::sanitize_post_data( 'rate' ) ) : 5;
		$message = Utility::sanitize_post_data( 'query_feedback' );
		$phone   = get_option( 'mo_saml_admin_phone', '' );

		if ( empty( $email ) || ! is_email( $email ) ) {
			Error_Success_Message::show_admin_notice( 'Please enter a valid email address.' );
			return;
		}

		$rate_messages = array(
			1 => 'Very Dissatisfied',
			2 => 'Dissatisfied',
			3 => 'Neutral',
			4 => 'Satisfied',
			5 => 'Very Satisfied',
		);

		$rate_message      = isset( $rate_messages[ $rate ] ) ? $rate_messages[ $rate ] : 'Not Specified';
		$feedback_message  = 'Plugin De-Activated [Reply: ' . ( Utility::sanitize_post_data( 'get_reply' ) ? 'Yes' : 'No' ) . ']';
		$feedback_message .= "Rating: {$rate_message} ({$rate}/5)\n\n";
		if ( ! empty( $message ) ) {
			$feedback_message .= "Feedback: {$message}\n\n";
		}

		$customer       = new Mo_Customer();
		$response       = $customer->mo_saml_send_email_alert( $email, $phone, $feedback_message );
		$deactivate_url = admin_url( 'plugins.php?action=deactivate&plugin=' . rawurlencode( plugin_basename( MOSAML_PLUGIN_FILE ) ) . '&_wpnonce=' . wp_create_nonce( 'deactivate-plugin_' . plugin_basename( MOSAML_PLUGIN_FILE ) ) );
		wp_safe_redirect( $deactivate_url );
		exit;
	}

	/**
	 * Display feedback form modal.
	 *
	 * @return void
	 */
	public function display_feedback_modal() {
		// Only show on plugins page and if feedback hasn't been submitted.
		$screen = get_current_screen();
		if ( ! $screen || 'plugins' !== $screen->id ) {
			return;
		}

		require_once Plugin_Files_Constants::TEMPLATE_FEEDBACK_FORM;
	}

	/**
	 * Get plugin directory URL.
	 *
	 * @return string
	 */
	public static function get_plugin_dir_url() {
		return plugins_url( '', MOSAML_PLUGIN_FILE );
	}
}
