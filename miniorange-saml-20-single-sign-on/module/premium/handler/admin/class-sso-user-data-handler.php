<?php
/**
 * SSO User Data Handler - Premium Module
 *
 * Extends the standard SSO user data handler to provide premium module functionality.
 *
 * @package miniorange-saml-20-single-sign-on
 * @subpackage Module\Premium\Handler\Admin
 */

namespace MOSAML\Module\Premium\Handler\Admin;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\Module\Standard\Handler\Admin\SSO_User_Data_Handler as Standard_SSO_User_Data_Handler;
use MOSAML\SRC\Interfaces\Form_Data_Handler_Interface;
use MOSAML\SRC\Utils\DB_Utils;
use MOSAML\SRC\Utils\Utility;
use MOSAML\SRC\Utils\Error_Success_Message;

/**
 * SSO User Data Handler.
 */
class SSO_User_Data_Handler extends Standard_SSO_User_Data_Handler implements Form_Data_Handler_Interface {

	/**
	 * Validate and save the SSO user configuration.
	 *
	 * @return void
	 */
	public function validate_and_save_data() {
		$this->sso_show_user = Utility::sanitize_post_data( 'mo_saml_sso_show_user' );

		$selected_environment_id   = DB_Utils::get_environment_details( 'id', false );
		$blog_id_for_environment = Utility::get_subsite_id_for_environment( $selected_environment_id );
		$default_idp_id            = DB_Utils::get_default_inserted_idp_details( 'id', $selected_environment_id );
		$table_data                = array(
			'option_name'  => 'sso_show_user',
			'option_value' => $this->sso_show_user,
			'idp_id'       => $default_idp_id,
			'subsite_id'   => $blog_id_for_environment,
		);

		$query_result = DB_Utils::insert_or_update(
			$this->get_table_name(),
			$table_data,
			array(
				'option_name' => 'sso_show_user',
				'idp_id'      => $default_idp_id,
				'subsite_id'  => $blog_id_for_environment,
			)
		);
		if ( $query_result ) {
			Error_Success_Message::show_admin_notice( 'Show SSO user in User settings updated.', 'SUCCESS' );
		}
	}

	/**
	 * Get the SSO user configuration.
	 *
	 * @param array $where The where clause to filter the data.
	 * @return object
	 */
	public function get_data( $where = array() ) {
		$where  = array_merge(
			array(
				'option_name' => 'sso_show_user',
			),
			$where
		);
		$record = DB_Utils::get_records( $this->get_table_name(), $where, true );
		if ( $record ) {
			$this->sso_show_user = $record->option_value;
		}
		return $this;
	}
}
