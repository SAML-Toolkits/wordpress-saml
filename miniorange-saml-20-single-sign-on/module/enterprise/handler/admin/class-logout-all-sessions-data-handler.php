<?php
/**
 * Logout All Sessions Data Handler file for enterprise plan.
 *
 * @package MOSAML\Module\Enterprise\Handler\Admin
 */

namespace MOSAML\Module\Enterprise\Handler\Admin;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\Module\Premium\Handler\Admin\Logout_All_Sessions_Data_Handler as Premium_Logout_All_Sessions_Data_Handler;
use MOSAML\SRC\Interfaces\Form_Data_Handler_Interface;
use MOSAML\SRC\Utils\DB_Utils;
use MOSAML\SRC\Utils\Utility;
use MOSAML\SRC\Utils\Error_Success_Message;
use MOSAML\SRC\Constant\Constants;

/**
 * Logout All Sessions Data Handler class for enterprise plan.
 */
class Logout_All_Sessions_Data_Handler extends Premium_Logout_All_Sessions_Data_Handler implements Form_Data_Handler_Interface {


	/**
	 * Validate and save the logout all sessions data.
	 *
	 * @return void
	 */
	public function validate_and_save_data() {
		$this->saml_force_complete_logout = Utility::sanitize_post_data( 'saml_force_complete_logout' );

		$is_enterprise      = 'ENTERPRISE' === Constants::VERSION_HIERARCHY[ MOSAML_VERSION ];
		$configured_idps_id = DB_Utils::get_configured_idps_details( 'idp_id', false, false );

		$selected_idp_id      = Utility::get_selected_idp_id_from_url( $is_enterprise, $configured_idps_id );
		$selected_idp_details = DB_Utils::get_records(
			Constants::DATABASE_TABLE_NAMES['idp_details'],
			array(
				'idp_id'         => $selected_idp_id,
				'environment_id' => DB_Utils::get_environment_details( 'id', false ),
			),
			true
		);

		$idp_id     = ! empty( $selected_idp_details ) ? $selected_idp_details->id : '';
		$table_data = array(
			'option_name'  => 'saml_force_complete_logout',
			'option_value' => $this->saml_force_complete_logout,
			'idp_id'       => $idp_id,
			'subsite_id'   => Utility::get_subsite_id_for_environment(),
		);

		$query_result = DB_Utils::insert_or_update(
			$this->get_table_name(),
			$table_data,
			array(
				'option_name' => 'saml_force_complete_logout',
				'idp_id'      => $idp_id,
				'subsite_id'  => Utility::get_subsite_id_for_environment(),
			)
		);
		if ( $query_result ) {
			Error_Success_Message::show_admin_notice( 'Force complete logout updated.', 'SUCCESS' );
		}
	}

	/**
	 * Get the logout all sessions data from the database.
	 *
	 * @param  array $where The where clause to filter the data.
	 * @return object
	 */
	public function get_data( $where = array() ) {

		$is_enterprise      = 'ENTERPRISE' === Constants::VERSION_HIERARCHY[ MOSAML_VERSION ];
		$configured_idps_id = DB_Utils::get_configured_idps_details( 'idp_id', false, false );
		$configured_idps    = DB_Utils::get_configured_idps_details( '', false, false );

		$idp_id = Utility::get_selected_idp_id_from_url( $is_enterprise, $configured_idps_id );

		if ( empty( $idp_id ) ) {
			$idp_id = DB_Utils::get_default_inserted_idp_details( 'id', DB_Utils::get_environment_details( 'id', false ) );
		} else {
			$selected_idp_details = DB_Utils::get_records(
				Constants::DATABASE_TABLE_NAMES['idp_details'],
				array(
					'idp_id'         => $idp_id,
					'environment_id' => DB_Utils::get_environment_details( 'id', false ),
				),
				true
			);

			$idp_id = ! empty( $selected_idp_details ) ? $selected_idp_details->id : '';
		}

		$where  = array_merge(
			array(
				'option_name' => 'saml_force_complete_logout',
				'idp_id'      => $idp_id,
				'subsite_id'  => Utility::get_subsite_id_for_environment(),
			),
			$where
		);
		$record = DB_Utils::get_records( $this->get_table_name(), $where, true );
		if ( $record ) {
			$this->saml_force_complete_logout = $record->option_value;
		}
		return $this;
	}
}
