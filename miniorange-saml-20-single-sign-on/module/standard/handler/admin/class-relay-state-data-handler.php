<?php
/**
 * Standard Relay State Data Handler.
 *
 * @package miniorange-saml-20-single-sign-on/module/standard/handler/admin
 */

namespace MOSAML\Module\Standard\Handler\Admin;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\Module\Base\Handler\Admin\Relay_State_Data_Handler as Base_Relay_State_Data_Handler;
use MOSAML\SRC\Interfaces\Form_Data_Handler_Interface;
use MOSAML\SRC\Utils\DB_Utils;
use MOSAML\SRC\Utils\Error_Success_Message;
use MOSAML\SRC\Utils\Utility;

/**
 * Standard Relay State Data Handler.
 */
class Relay_State_Data_Handler extends Base_Relay_State_Data_Handler implements Form_Data_Handler_Interface {

	/**
	 * Validate and save the data.
	 * Standard version only handles login relay state. Logout relay state is a premium feature.
	 *
	 * @return void
	 */
	public function validate_and_save_data() {
		$idp_id = Utility::sanitize_post_data( 'mo_saml_relay_state_idp_name' );
		if ( empty( $idp_id ) || 'DEFAULT' === $idp_id ) {
			$idp_id = DB_Utils::get_default_inserted_idp_details( 'id', false );
		}

		if ( is_null( $idp_id ) ) {
			return;
		}

		$this->login_relay_state = Utility::sanitize_post_data( 'mo_saml_login_relay_state' );

		if ( empty( $this->login_relay_state ) ) {
			$this->insert_or_update_setting( 'login_relay_state', '', $idp_id );
		} elseif ( Utility::is_3rd_party_url( $this->login_relay_state ) ) {
			Error_Success_Message::show_admin_notice( '3rd party URL detected. Please enter URL of the current site.' );
		} elseif ( filter_var( $this->login_relay_state, FILTER_VALIDATE_URL ) !== false ) {
			$this->insert_or_update_setting( 'login_relay_state', $this->login_relay_state, $idp_id );
		} else {
			Error_Success_Message::show_admin_notice( 'Please enter a valid Login Relay State URL.' );
		}
	}

	/**
	 * Get the data.
	 * Standard version only retrieves login relay state. Logout relay state is a premium feature.
	 *
	 * @param array $where The where clause to filter the data.
	 * @return object The data.
	 */
	public function get_data( $where = array() ) {
		if ( Utility::is_legacy_data_fallback_required() ) {
			return apply_filters( 'mosaml_legacy_data_fallback_object', $this, $where );
		}
		$idp_id = isset( $where['idp_id'] ) ? $where['idp_id'] : null;

		if ( is_null( $idp_id ) ) {
			$idp_id = Utility::sanitize_request_data( 'idp_id', false, 'DEFAULT' );
		}

		if ( 'DEFAULT' === $idp_id || empty( $idp_id ) ) {
			$idp_id = DB_Utils::get_default_inserted_idp_details( 'id', false );
		}

		if ( is_null( $idp_id ) ) {
			return $this;
		}

		$login = $this->get_setting_value( 'login_relay_state', $idp_id );
		if ( ! is_null( $login ) ) {
			$this->login_relay_state = $login;
		}
		return $this;
	}

	/**
	 * Insert or update a setting in the database.
	 *
	 * @param string $option_name The option name.
	 * @param mixed  $option_value The option value.
	 * @param int    $idp_id The IDP ID.
	 * @return void
	 */
	protected function insert_or_update_setting( $option_name, $option_value, $idp_id ) {
		$table_data = array(
			'option_name'  => $option_name,
			'option_value' => $option_value,
			'subsite_id'   => Utility::get_subsite_id_for_environment(),
			'idp_id'       => $idp_id,
		);

		DB_Utils::insert_or_update(
			$this->get_table_name(),
			$table_data,
			array(
				'option_name' => $option_name,
				'idp_id'      => (int) $idp_id,
				'subsite_id'  => Utility::get_subsite_id_for_environment(),
			)
		);
		Error_Success_Message::show_admin_notice( 'Relay State updated successfully.', 'SUCCESS' );
	}

	/**
	 * Get a setting value from the database.
	 *
	 * @param string $option_name The option name.
	 * @param int    $idp_id The IDP ID.
	 * @return string|null The option value or null if not found.
	 */
	protected function get_setting_value( $option_name, $idp_id ) {
		$record = DB_Utils::get_records(
			$this->get_table_name(),
			array(
				'option_name' => $option_name,
				'idp_id'      => $idp_id,
				'subsite_id'  => Utility::get_subsite_id_for_environment(),
			),
			true
		);

		return $record ? $record->option_value : null;
	}
}
