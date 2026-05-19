<?php
/**
 * This file contains the backend operations related to the Role Mapping tab for the base module.
 *
 * @package MOSAML
 */

namespace MOSAML\Module\Base\Handler\Admin;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\SRC\Interfaces\Form_Data_Handler_Interface;
use MOSAML\SRC\Utils\DB_Utils;
use MOSAML\SRC\Utils\Error_Success_Message;
use MOSAML\SRC\Utils\Utility;
use MOSAML\SRC\Constant\Constants;

/**
 * Role Mapping Data Handler.
 */
class Role_Mapping_Data_Handler implements Form_Data_Handler_Interface {

	/**
	 * Role mapping values.
	 *
	 * @var array
	 */
	public $role_mapping_values = array();

	/**
	 * Validate and save the data for the Role Mapping tab.
	 *
	 * @return void
	 */
	public function validate_and_save_data() {
		$idp_id = Utility::sanitize_post_data( 'selected_idp_id' );
		if ( ! $idp_id ) {
			return;
		}

		DB_Utils::delete_records(
			$this->get_table_name(),
			array(
				'idp_id'     => $idp_id,
				'subsite_id' => Utility::get_subsite_id_for_environment(),
			)
		);

		foreach ( $this->role_mapping_values as $option_name => $option_value ) {
			foreach ( explode( ';', $option_value ) as $role_value ) {
				$option_value = trim( $role_value );
				if ( empty( $option_value ) ) {
					continue;
				}
				DB_Utils::insert_or_update(
					$this->get_table_name(),
					array(
						'role_name'      => $option_name,
						'idp_group_name' => $option_value,
						'idp_id'         => $idp_id,
						'subsite_id'     => Utility::get_subsite_id_for_environment(),
					),
					array(
						'role_name'      => $option_name,
						'idp_group_name' => $option_value,
						'idp_id'         => $idp_id,
						'subsite_id'     => Utility::get_subsite_id_for_environment(),
					)
				);
			}
		}
		Error_Success_Message::show_admin_notice( 'Role Mapping details saved successfully.', 'SUCCESS' );
	}

	/**
	 * Get the data for the Role Mapping tab.
	 *
	 * @param array $where The where clause to filter the data.
	 * @return object The data for the Role Mapping tab.
	 */
	public function get_data( $where = array() ) {

		$role_mapping_data = DB_Utils::get_records(
			$this->get_table_name(),
			$where
		);
		if ( ! is_countable( $role_mapping_data ) ) {
			return $this;
		}

		$role_mapping = array();
		foreach ( $role_mapping_data as $item ) {
			$existing = isset( $role_mapping[ $item->role_name ] ) ? $role_mapping[ $item->role_name ] : '';
			if ( ! empty( $existing ) && ! empty( $item->idp_group_name ) ) {
				$role_mapping[ $item->role_name ] = $existing . ';' . $item->idp_group_name;
			} else {
				$role_mapping[ $item->role_name ] = $item->idp_group_name;
			}
		}
		$this->role_mapping_values = $role_mapping;
		return $this;
	}

	/**
	 * Get the table name.
	 *
	 * @return string The table name.
	 */
	public function get_table_name() {
		return Constants::DATABASE_TABLE_NAMES['role_mapping'];
	}

	/**
	 * Delete the data for the Role Mapping tab.
	 *
	 * @return void
	 */
	public function delete_data() {
		$selected_idp = Utility::sanitize_get_data( 'idp' );
		$idp_details  = DB_Utils::get_records( Constants::DATABASE_TABLE_NAMES['idp_details'], array( 'idp_id' => $selected_idp ), true );
		if ( empty( $idp_details ) ) {
			return;
		}
		$idp_id = $idp_details->id;

		DB_Utils::delete_records(
			$this->get_table_name(),
			array(
				'idp_id'     => $idp_id,
				'subsite_id' => Utility::get_subsite_id_for_environment(),
			)
		);
		Error_Success_Message::show_admin_notice( 'Role Mapping configurations reset successfully.', 'SUCCESS' );
	}

	/**
	 * Save the data for the Role Mapping tab.
	 *
	 * @param object $data The data to save.
	 * @param array  $details The details array.
	 * @return void
	 */
	public function save_data( $data, $details = array() ) {
		$selected_environment_id = ! empty( $details['environment_url'] ) ? DB_Utils::get_records( Constants::DATABASE_TABLE_NAMES['environments'], array( 'environment_url' => $details['environment_url'] ), true )->id : DB_Utils::get_environment_details( 'id', false );
		$blog_id_for_environment = Utility::get_subsite_id_for_environment( $selected_environment_id );
		$idp                     = null;
		if ( ! empty( $details['idp_id'] ) ) {
			$idp = 'DEFAULT' === $details['idp_id'] ? DB_Utils::get_records(
				Constants::DATABASE_TABLE_NAMES['idp_details'],
				array(
					'environment_id' => $selected_environment_id,
					'idp_name'       => 'ALL IDPs',
				),
				true
			) : DB_Utils::get_records( Constants::DATABASE_TABLE_NAMES['idp_details'], array( 'idp_id' => $details['idp_id'] ), true );
		}
		$selected_idp = ! is_null( $idp ) ? $idp->id : Utility::get_default_idp( $selected_environment_id )->id;

		foreach ( $this->role_mapping_values as $option_name => $option_value ) {
			foreach ( explode( ';', $option_value ) as $role_value ) {
				$option_value = trim( $role_value );
				if ( empty( $option_value ) ) {
					continue;
				}
				DB_Utils::insert_or_update(
					$this->get_table_name(),
					array(
						'role_name'      => $option_name,
						'idp_group_name' => $option_value,
						'idp_id'         => $selected_idp,
						'subsite_id'     => $blog_id_for_environment,
					),
					array(
						'role_name'      => $option_name,
						'idp_group_name' => $option_value,
						'idp_id'         => $selected_idp,
						'subsite_id'     => $blog_id_for_environment,
					)
				);
			}
		}
	}
}
