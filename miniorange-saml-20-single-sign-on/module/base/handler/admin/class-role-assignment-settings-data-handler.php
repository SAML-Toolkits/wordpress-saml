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

use MOSAML\SRC\Constant\Constants;
use MOSAML\SRC\Interfaces\Form_Data_Handler_Interface;
use MOSAML\SRC\Utils\DB_Utils;
use MOSAML\SRC\Utils\Error_Success_Message;
use MOSAML\SRC\Utils\Utility;

/**
 * Default Role Settings Data Handler.
 */
class Role_Assignment_Settings_Data_Handler implements Form_Data_Handler_Interface {

	/**
	 * Group attribute name.
	 *
	 * @var string
	 */
	public $group_attribute_name;

	/**
	 * Create new user with role.
	 *
	 * @var boolean
	 */
	public $create_new_user = 'checked';

	/**
	 * Update existing user.
	 *
	 * @var boolean
	 */
	public $update_existing_user;

	/**
	 * Default role existing.
	 *
	 * @var string
	 */
	public $default_role_existing;

	/**
	 * Apply role mapping to admin.
	 *
	 * @var boolean
	 */
	public $apply_role_mapping_to_admin;

	/**
	 * Default role new.
	 *
	 * @var string
	 */
	public $default_role_new;

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

		if ( 'checked' === $this->create_new_user ) {
			$this->default_role_new = Utility::sanitize_post_data( 'mo_saml_default_role_new' );
			if ( empty( $this->default_role_new ) ) {
				$this->default_role_new = get_option( 'default_role' );
			}
		}

		$object_vars = get_object_vars( $this );

		if ( 'checked' !== $this->create_new_user ) {
			unset( $object_vars['default_role_new'] );
		}

		if ( 'checked' !== $this->update_existing_user ) {
			unset( $object_vars['default_role_existing'] );
		}

		foreach ( $object_vars as $option_name => $option_value ) {
			if ( null === $option_value ) {
				continue;
			}
			DB_Utils::insert_or_update(
				$this->get_table_name(),
				array(
					'option_name'  => $option_name,
					'option_value' => $option_value,
					'idp_id'       => $idp_id,
					'subsite_id'   => Utility::get_subsite_id_for_environment(),
				),
				array(
					'option_name' => $option_name,
					'idp_id'      => $idp_id,
					'subsite_id'  => Utility::get_subsite_id_for_environment(),
				)
			);
		}

		DB_Utils::insert_or_update(
			$this->get_table_name(),
			array(
				'option_name'  => 'role_assignment_settings_recorded',
				'option_value' => true,
				'idp_id'       => $idp_id,
				'subsite_id'   => Utility::get_subsite_id_for_environment(),
			),
			array(
				'option_name' => 'role_assignment_settings_recorded',
				'idp_id'      => $idp_id,
				'subsite_id'  => Utility::get_subsite_id_for_environment(),
			)
		);

		Error_Success_Message::show_admin_notice( 'Role Mapping details saved successfully.', 'SUCCESS' );
	}

	/**
	 * Get the data for the Role Mapping tab.
	 *
	 * @param array $where The where clause to filter the data.
	 * @return object The data for the Role Mapping tab.
	 */
	public function get_data( $where = array() ) {
		$where = array_merge(
			array( 'option_name' => array_keys( get_object_vars( $this ) ) ),
			$where
		);

		if ( Utility::is_legacy_data_fallback_required() ) {
			$result = apply_filters( 'mosaml_legacy_data_fallback_object', $this, $where );
			if ( ! $result->default_role_new ) {
				$result->default_role_new = get_option( 'default_role' );
			}
			if ( ! $result->default_role_existing ) {
				$result->default_role_existing = get_option( 'default_role' );
			}
			return $result;
		}

		$default_role_settings = DB_Utils::get_records(
			$this->get_table_name(),
			$where
		);
		if ( ! is_countable( $default_role_settings ) ) {
			return $this;
		}
		foreach ( $default_role_settings as $default_role_setting ) {
			$this->{$default_role_setting->option_name} = maybe_unserialize( $default_role_setting->option_value );
		}

		if ( ! $this->default_role_new ) {
			$this->default_role_new = get_option( 'default_role' );
		}

		if ( ! $this->default_role_existing ) {
			$this->default_role_existing = get_option( 'default_role' );
		}

		return $this;
	}

	/**
	 * Get the table name.
	 *
	 * @return string The table name.
	 */
	public function get_table_name() {
		return Constants::DATABASE_TABLE_NAMES['sso_settings'];
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

		foreach ( array_keys( get_object_vars( $this ) ) as $option_name ) {
			DB_Utils::delete_records(
				$this->get_table_name(),
				array(
					'idp_id'      => $idp_id,
					'option_name' => $option_name,
					'subsite_id'  => Utility::get_subsite_id_for_environment(),
				)
			);
		}
		DB_Utils::delete_records(
			$this->get_table_name(),
			array(
				'option_name' => 'role_assignment_settings_recorded',
				'idp_id'      => $idp_id,
				'subsite_id'  => Utility::get_subsite_id_for_environment(),
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

		foreach ( get_object_vars( $this ) as $option_name => $option_value ) {
			if ( empty( $option_value ) ) {
				continue;
			}
			DB_Utils::insert_or_update(
				$this->get_table_name(),
				array(
					'option_name'  => $option_name,
					'option_value' => $option_value,
					'idp_id'       => $selected_idp,
					'subsite_id'   => $blog_id_for_environment,
				),
				array(
					'option_name' => $option_name,
					'idp_id'      => $selected_idp,
					'subsite_id'  => $blog_id_for_environment,
				)
			);
		}

		DB_Utils::insert_or_update(
			$this->get_table_name(),
			array(
				'option_name'  => 'role_assignment_settings_recorded',
				'option_value' => true,
				'idp_id'       => $selected_idp,
				'subsite_id'   => get_current_blog_id(),
			),
			array(
				'option_name' => 'role_assignment_settings_recorded',
				'idp_id'      => $selected_idp,
				'subsite_id'  => get_current_blog_id(),
			)
		);
	}
}
