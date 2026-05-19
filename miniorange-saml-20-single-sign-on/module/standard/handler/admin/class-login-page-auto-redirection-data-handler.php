<?php
/**
 * Standard Redirect From WP Login Form Data Handler
 *
 * @package miniorange-saml-20-single-sign-on/module/standard/handler/admin
 */

namespace MOSAML\Module\Standard\Handler\Admin;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\Module\Base\Handler\Admin\Login_Page_Auto_Redirection_Data_Handler as Base_Login_Page_Auto_Redirection_Data_Handler;
use MOSAML\SRC\Utils\Utility;
use MOSAML\SRC\Utils\Error_Success_Message;
use MOSAML\SRC\Utils\DB_Utils;

/**
 * Standard Redirect From WP Login Form Data Handler
 *
 * Extends base functionality with standard-specific features for redirecting from WordPress login form.
 */
class Login_Page_Auto_Redirection_Data_Handler extends Base_Login_Page_Auto_Redirection_Data_Handler {

	/**
	 * Validate and save the data.
	 *
	 * @return void
	 */
	public function validate_and_save_data() {
		$this->redirect_from_wp_login = Utility::sanitize_post_data( 'mo_saml_enable_login_redirect' );

		$idp_id       = DB_Utils::get_default_inserted_idp_details( 'id', DB_Utils::get_environment_details( 'id', false ) );
		$query_result = DB_Utils::insert_or_update(
			$this->get_table_name(),
			array(
				'option_name'  => 'redirect_from_wp_login',
				'option_value' => $this->redirect_from_wp_login,
				'subsite_id'   => Utility::get_subsite_id_for_environment(),
				'idp_id'       => $idp_id,
			),
			array(
				'option_name' => 'redirect_from_wp_login',
				'subsite_id'  => Utility::get_subsite_id_for_environment(),
				'idp_id'      => $idp_id,
			)
		);
		if ( 'checked' === $this->redirect_from_wp_login ) {
			DB_Utils::insert_or_update(
				$this->get_table_name(),
				array(
					'option_name'  => 'enable_backdoor_url_login',
					'option_value' => 'checked',
					'subsite_id'   => Utility::get_subsite_id_for_environment(),
					'idp_id'       => $idp_id,
				),
				array(
					'option_name' => 'enable_backdoor_url_login',
					'subsite_id'  => Utility::get_subsite_id_for_environment(),
					'idp_id'      => $idp_id,
				)
			);
		}
		if ( $query_result ) {
			Error_Success_Message::show_admin_notice( 'Sign in options updated.', 'SUCCESS' );
		}
	}

	/**
	 * Get the data.
	 *
	 * @param array $where The where clause to filter the data.
	 * @return object The data.
	 */
	public function get_data( $where = array() ) {
		$where  = array_merge(
			array(
				'option_name' => 'redirect_from_wp_login',
				'subsite_id'  => Utility::get_subsite_id_for_environment(),
			),
			$where
		);
		$record = DB_Utils::get_records(
			$this->get_table_name(),
			$where,
			true
		);
		if ( $record ) {
			$this->redirect_from_wp_login = $record->option_value;
		}

		return parent::get_data( $where );
	}
}
