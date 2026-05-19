<?php
/**
 * Hide WP Login Data Handler - Enterprise Module
 *
 * Extends the premium hide-wp-login data handler to provide enterprise module functionality.
 *
 * PHP Compatibility: 5.6+
 *
 * @package miniorange-saml-20-single-sign-on
 */

namespace MOSAML\Module\Enterprise\Handler\Admin;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\Module\Premium\Handler\Admin\Hide_WP_Login_Data_Handler as Premium_Hide_WP_Login_Data_Handler;
use MOSAML\SRC\Interfaces\Form_Data_Handler_Interface;
use MOSAML\SRC\Utils\DB_Utils;
use MOSAML\SRC\Utils\Utility;
use MOSAML\SRC\Utils\Error_Success_Message;

/**
 * Hide WP Login Data Handler.
 */
class Hide_WP_Login_Data_Handler extends Premium_Hide_WP_Login_Data_Handler implements Form_Data_Handler_Interface {
	/**
	 * Validate and save the hide WP login configuration.
	 *
	 * @return void
	 */
	public function validate_and_save_data() {

		$this->hide_wp_login = Utility::sanitize_post_data( 'mo_saml_enable_hide_wp_login' );

		if ( $this->hide_wp_login ) {
			$sso_button_handler = Utility::get_handler_object( 'sso_button_data', true, 'admin' );
			if ( ! $sso_button_handler->get_enabled_sso_button_count() ) {
				Error_Success_Message::show_admin_notice( 'Hiding the login form requires at least one active SSO login button.', 'ERROR' );
				return;
			}
		}

		$default_idp_id = DB_Utils::get_default_inserted_idp_details( 'id', DB_Utils::get_environment_details( 'id', false ) );

		$table_data = array(
			'option_name'  => 'hide_wp_login',
			'option_value' => $this->hide_wp_login,
			'idp_id'       => $default_idp_id,
			'subsite_id'   => Utility::get_subsite_id_for_environment(),
		);

		DB_Utils::insert_or_update(
			$this->get_table_name(),
			$table_data,
			array(
				'option_name' => 'hide_wp_login',
				'idp_id'      => $default_idp_id,
				'subsite_id'  => Utility::get_subsite_id_for_environment(),
			)
		);

		if ( $this->hide_wp_login ) {
			Error_Success_Message::show_admin_notice( 'WordPress Default Login Form has been disabled.', 'SUCCESS' );
		} else {
			Error_Success_Message::show_admin_notice( 'WordPress Default Login Form has been enabled.', 'SUCCESS' );
		}
	}

	/**
	 * Get the hide WP login configuration.
	 *
	 * @param array $where The where clause to filter the data.
	 * @return object
	 */
	public function get_data( $where = array() ) {
		$where  = array_merge( $where, array( 'option_name' => 'hide_wp_login' ) );
		$record = DB_Utils::get_records( $this->get_table_name(), $where, true );

		if ( $record ) {
			$this->hide_wp_login = $record->option_value;
		}

		return $this;
	}
}
