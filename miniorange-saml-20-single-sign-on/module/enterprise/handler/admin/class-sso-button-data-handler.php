<?php
/**
 * SSO Button Data Handler - Enterprise Module
 *
 * Extends the premium SSO button data handler to provide enterprise module functionality.
 *
 * PHP Compatibility: 5.6+
 *
 * @package miniorange-saml-20-single-sign-on
 */

namespace MOSAML\Module\Enterprise\Handler\Admin;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\Module\Premium\Handler\Admin\SSO_Button_Data_Handler as Premium_SSO_Button_Data_Handler;
use MOSAML\SRC\Interfaces\Form_Data_Handler_Interface;
use MOSAML\SRC\Utils\Utility;
use MOSAML\SRC\Utils\DB_Utils;
use MOSAML\SRC\Utils\Error_Success_Message;

/**
 * SSO Button Data Handler.
 */
class SSO_Button_Data_Handler extends Premium_SSO_Button_Data_Handler implements Form_Data_Handler_Interface {

	/**
	 * Validate and save the SSO button configuration.
	 *
	 * @return void
	 */
	public function validate_and_save_data() {

		$this->enable_sso_button = Utility::sanitize_post_data( 'mo_saml_add_sso_button_wp' );

		if ( empty( $this->enable_sso_button ) || 'checked' !== $this->enable_sso_button ) {
			$hide_wp_login_handler = Utility::get_handler_object( 'hide_wp_login_data', true, 'admin' );
			$hide_wp_login_handler->get_data( array( 'subsite_id' => Utility::get_subsite_id_for_environment() ) );

			$enabled_sso_button_count = $this->get_enabled_sso_button_count();
			$hide_login_form_enabled  = ! empty( $hide_wp_login_handler->hide_wp_login ) && 'checked' === $hide_wp_login_handler->hide_wp_login;
			if ( $hide_login_form_enabled && $enabled_sso_button_count <= 1 ) {
				Error_Success_Message::show_admin_notice( 'Hiding the login form requires at least one active SSO login button.', 'ERROR' );
				return;
			}
		}

		parent::validate_and_save_data();
	}

	/**
	 * Get count of checked SSO button records for the current subsite.
	 *
	 * @return int Number of enabled SSO buttons.
	 */
	public function get_enabled_sso_button_count() {
		$records = $this->get_sso_button_option_records();
		$count   = 0;
		if ( empty( $records ) ) {
			$count = "checked" === $this->get_data()->enable_sso_button ? 1 : 0 ; // checking if by default button is set.
		}
		foreach ( $records as $record ) {
			if ( 'checked' === $record->option_value && null !== $record->idp_id ) {
				++$count;
			}
		}
		return $count;
	}

	/**
	 * Get SSO button option records for the current subsite.
	 *
	 * @return array List of record objects.
	 */
	private function get_sso_button_option_records() {
		$records = DB_Utils::get_records(
			$this->get_table_name(),
			array(
				'option_name' => 'enable_sso_button',
				'subsite_id'  => Utility::get_subsite_id_for_environment(),
			)
		);
		return is_array( $records ) ? $records : array();
	}
}
