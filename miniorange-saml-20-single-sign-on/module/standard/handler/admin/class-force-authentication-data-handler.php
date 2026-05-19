<?php
/**
 * Standard Force Authentication Data Handler.
 *
 * @package miniorange-saml-20-single-sign-on/module/standard/handler/admin
 */

namespace MOSAML\Module\Standard\Handler\Admin;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\Module\Base\Handler\Admin\Force_Authentication_Data_Handler as Base_Force_Authentication_Data_Handler;
use MOSAML\SRC\Interfaces\Form_Data_Handler_Interface;
use MOSAML\SRC\Utils\Utility;
use MOSAML\SRC\Utils\Error_Success_Message;
use MOSAML\SRC\Utils\DB_Utils;

/**
 * Standard Force Authentication Data Handler.
 */
class Force_Authentication_Data_Handler extends Base_Force_Authentication_Data_Handler implements Form_Data_Handler_Interface {

	/**
	 * Validate and save data.
	 *
	 * @return void
	 */
	public function validate_and_save_data() {
		$this->enable_force_authentication = Utility::sanitize_post_data( 'mo_saml_force_authentication' );

		$idp_id = DB_Utils::get_default_inserted_idp_details( 'id', DB_Utils::get_environment_details( 'id', false ) );
		if ( is_null( $idp_id ) ) {
			return;
		}

		if ( ! is_null( $this->enable_force_authentication ) ) {
			$table_data = array(
				'option_name'  => 'enable_force_authentication',
				'option_value' => $this->enable_force_authentication,
				'subsite_id'   => Utility::get_subsite_id_for_environment(),
				'idp_id'       => $idp_id,
			);

			$query_result = DB_Utils::insert_or_update(
				$this->get_table_name(),
				$table_data,
				array(
					'option_name' => 'enable_force_authentication',
					'idp_id'      => $idp_id,
					'subsite_id'  => Utility::get_subsite_id_for_environment(),
				)
			);
			if ( $query_result ) {
				Error_Success_Message::show_admin_notice( 'Auto redirection from site options saved successfully.', 'SUCCESS' );
			}
		}
	}

	/**
	 * Get data from the database.
	 *
	 * @param array $where Where clause.
	 * @return object
	 */
	public function get_data( $where = array() ) {
		$where = array_merge(
			array(
				'option_name' => 'enable_force_authentication',
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
			$this->enable_force_authentication = $record->option_value;
		}

		return $this;
	}
}
