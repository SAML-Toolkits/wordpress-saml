<?php
/**
 * Backdoor Login Form Data Handler - Standard Module
 *
 * Extends the base backdoor login form data handler to provide standard module functionality.
 *
 * PHP Compatibility: 5.6+
 *
 * @package miniorange-saml-20-single-sign-on
 * @subpackage Module\Standard\Handler\Admin
 */

namespace MOSAML\Module\Standard\Handler\Admin;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\Module\Base\Handler\Admin\Backdoor_Url_Login_Data_Handler as Base_Backdoor_Url_Login_Data_Handler;
use MOSAML\SRC\Utils\Utility;
use MOSAML\SRC\Utils\DB_Utils;
use MOSAML\SRC\Utils\Error_Success_Message;
use MOSAML\SRC\Interfaces\Form_Data_Handler_Interface;

/**
 * Backdoor Login Form Data Handler.
 */
class Backdoor_Url_Login_Data_Handler extends Base_Backdoor_Url_Login_Data_Handler implements Form_Data_Handler_Interface {

	/**
	 * Validate and save the backdoor login form configuration.
	 *
	 * @return void
	 */
	public function validate_and_save_data() {
		$this->enable_backdoor_url_login = Utility::sanitize_post_data( 'mo_saml_allow_wp_signin' );

		$selected_environment_id = DB_Utils::get_environment_details( 'id', false );
		$idp_id                    = DB_Utils::get_default_inserted_idp_details( 'id', $selected_environment_id );
		DB_Utils::insert_or_update(
			$this->get_table_name(),
			array(
				'option_name'  => 'enable_backdoor_url_login',
				'option_value' => $this->enable_backdoor_url_login,
				'subsite_id'   => Utility::get_subsite_id_for_environment( $selected_environment_id ),
				'idp_id'       => $idp_id,
			),
			array(
				'option_name' => 'enable_backdoor_url_login',
				'subsite_id'  => Utility::get_subsite_id_for_environment( $selected_environment_id ),
				'idp_id'      => $idp_id,
			)
		);
		if ( 'checked' === $this->enable_backdoor_url_login ) {
			$this->backdoor_url = Utility::sanitize_post_data( 'mo_saml_backdoor_url' ) ? Utility::sanitize_post_data( 'mo_saml_backdoor_url' ) : 'false';
			if ( ! preg_match( '/^[a-zA-Z0-9_\-]+$/', $this->backdoor_url ) ) {
				Error_Success_Message::show_admin_notice( 'Only alphanumeric character are allowed. Also the field cannot be empty.' );
				return;
			}
			DB_Utils::insert_or_update(
				$this->get_table_name(),
				array(
					'option_name'  => 'backdoor_url',
					'option_value' => $this->backdoor_url,
					'subsite_id'   => Utility::get_subsite_id_for_environment( $selected_environment_id ),
					'idp_id'       => $idp_id,
				),
				array(
					'option_name' => 'backdoor_url',
					'subsite_id'  => Utility::get_subsite_id_for_environment( $selected_environment_id ),
					'idp_id'      => $idp_id,
				)
			);
		}
		Error_Success_Message::show_admin_notice( 'Sign in options updated.', 'SUCCESS' );
	}

	/**
	 * Get the backdoor login form configuration.
	 *
	 * @param array $where The where clause to filter the data.
	 * @return object The data.
	 */
	public function get_data( $where = array() ) {
		$backdoor_url_login_where = array_merge(
			array(
				'option_name' => 'enable_backdoor_url_login',
				'subsite_id'  => Utility::get_subsite_id_for_environment(),
			),
			$where
		);

		$record = DB_Utils::get_records(
			$this->get_table_name(),
			$backdoor_url_login_where,
			true
		);
		if ( $record ) {
			$this->enable_backdoor_url_login = $record->option_value;
		}

		$backdoor_url_where = array_merge(
			array(
				'option_name' => 'backdoor_url',
				'subsite_id'  => Utility::get_subsite_id_for_environment(),
			),
			$where
		);

		$record = DB_Utils::get_records(
			$this->get_table_name(),
			$backdoor_url_where,
			true
		);
		if ( $record ) {
			$this->backdoor_url = $record->option_value;
		}

		return parent::get_data( $where );
	}
}
