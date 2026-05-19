<?php
/**
 * Support form UI handler.
 *
 * @package miniorange-saml-20-single-sign-on
 */

namespace MOSAML\SRC\Handler\UI;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\SRC\Interfaces\Tab_UI_Handler_Interface;
use MOSAML\SRC\Constant\Plugin_Files_Constants;

/**
 * Handles rendering of the sidebar support form.
 */
class Support_Form_UI_Handler implements Tab_UI_Handler_Interface {

	/**
	 * Render the support form UI with prefilled values.
	 *
	 * @return void
	 */
	public function render_ui() {
		$admin_email = $this->get_admin_email();
		$admin_phone = $this->get_admin_phone();

		require_once Plugin_Files_Constants::TEMPLATE_SUPPORT_FORM;
	}

	/**
	 * Determine the email to prefill in the support form.
	 *
	 * @return string
	 */
	private function get_admin_email() {
		$email = get_option( 'mo_saml_admin_email', '' );

		if ( empty( $email ) ) {
			$current_user = wp_get_current_user();
			if ( $current_user && $current_user->exists() ) {
				$email = $current_user->user_email;
			} else {
				$email = get_option( 'admin_email', '' );
			}
		}

		return sanitize_email( $email );
	}

	/**
	 * Determine the phone number to prefill in the support form.
	 *
	 * @return string
	 */
	private function get_admin_phone() {
		$phone = sanitize_text_field( get_option( 'mo_saml_admin_phone', '' ) );

		if ( '' === $phone ) {
			$phone = '+1';
		}

		return $phone;
	}
}
