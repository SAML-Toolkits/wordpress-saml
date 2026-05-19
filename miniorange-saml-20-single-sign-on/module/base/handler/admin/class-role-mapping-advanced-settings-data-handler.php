<?php
/**
 * This file contains the backend operations related to the Role Mapping Advanced Settings tab for the base module.
 *
 * @package MOSAML
 */

namespace MOSAML\Module\Base\Handler\Admin;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\SRC\Interfaces\Form_Data_Handler_Interface;
use MOSAML\SRC\Constant\Constants;
use MOSAML\SRC\Utils\DB_Utils;
use MOSAML\SRC\Utils\Error_Success_Message;
use MOSAML\SRC\Utils\Utility;

/**
 * Role Mapping Advanced Settings Data Handler.
 */
class Role_Mapping_Advanced_Settings_Data_Handler implements Form_Data_Handler_Interface {

	/**
	 * Do not create new users.
	 *
	 * @var bool
	 */
	public $do_not_create_new_users;

	/**
	 * Do not update existing user roles.
	 *
	 * @var bool
	 */
	public $do_not_update_existing_user_roles;

	/**
	 * Whitelist existing users roles.
	 *
	 * @var bool
	 */
	public $whitelist_existing_users_roles;

	/**
	 * Whitelisted roles.
	 *
	 * @var string
	 */
	public $whitelisted_roles;

	/**
	 * Allow/Deny IDP attribute toggle.
	 *
	 * @var bool
	 */
	public $allow_deny_idp_attribute_toggle;

	/**
	 * Attribute restriction group.
	 *
	 * @var string
	 */
	public $attribute_restriction_group;

	/**
	 * Attribute restriction value.
	 *
	 * @var string
	 */
	public $attribute_restriction_value;

	/**
	 * Allow/Deny IDP attribute.
	 *
	 * @var string
	 */
	public $allow_deny_idp_attribute = 'allow';

	/**
	 * Allow/Deny user domain toggle.
	 *
	 * @var bool
	 */
	public $allow_deny_user_domain_toggle;

	/**
	 * Allow/Deny user domain value.
	 *
	 * @var string
	 */
	public $allow_deny_user_domain_value;

	/**
	 * Allow/Deny user domain type.
	 *
	 * @var string
	 */
	public $allow_deny_user_domain_type = 'allow';

	/**
	 * Enable regex for role mapping.
	 *
	 * @var bool
	 */
	public $enable_regex_for_role_mapping;


	/**
	 * Save the data for the Role Mapping Advanced Settings tab.
	 *
	 * @return void
	 */
	public function validate_and_save_data() {
		$selected_idp = Utility::sanitize_post_data( 'selected_idp_name' );
		if ( empty( $selected_idp ) ) {
			return;
		}
		$advanced_settings_data_properties = get_object_vars( $this );
		foreach ( $advanced_settings_data_properties as $option_name => $option_value ) {
			DB_Utils::insert_or_update(
				$this->get_table_name(),
				array(
					'option_name'  => $option_name,
					'option_value' => $option_value,
					'idp_id'       => $selected_idp,
					'subsite_id'   => Utility::get_subsite_id_for_environment(),
				),
				array(
					'option_name' => $option_name,
					'idp_id'      => $selected_idp,
					'subsite_id'  => Utility::get_subsite_id_for_environment(),
				)
			);
		}

		DB_Utils::insert_or_update(
			$this->get_table_name(),
			array(
				'option_name'  => 'attr_role_advanced_settings_recorded',
				'option_value' => true,
				'idp_id'       => $selected_idp,
				'subsite_id'   => Utility::get_subsite_id_for_environment(),
			),
			array(
				'option_name' => 'attr_role_advanced_settings_recorded',
				'idp_id'      => $selected_idp,
				'subsite_id'  => Utility::get_subsite_id_for_environment(),
			)
		);

		Error_Success_Message::show_admin_notice( 'Advanced Settings saved successfully.', 'SUCCESS' );
	}

	/**
	 * Get the data for the Role Mapping Advanced Settings tab.
	 *
	 * @param array $where The where clause to filter the data.
	 * @return object The data object.
	 */
	public function get_data( $where = array() ) {
		$where                  = array_merge(
			array(
				'option_name' => array_keys( get_object_vars( $this ) ),
			),
			$where
		);
		$advanced_settings_data = DB_Utils::get_records( $this->get_table_name(), $where );
		if ( ! is_countable( $advanced_settings_data ) ) {
			return $this;
		}
		foreach ( $advanced_settings_data as $data ) {
			if ( ( 'allow_deny_user_domain_type' === $data->option_name || 'allow_deny_idp_attribute' === $data->option_name ) && ! $data->option_value ) {
				continue;
			}
			$this->{$data->option_name} = maybe_unserialize( $data->option_value );
		}
		return $this;
	}

	/**
	 * Get the table name for the Role Mapping Advanced Settings tab.
	 *
	 * @return string The table name.
	 */
	public function get_table_name() {
		return Constants::DATABASE_TABLE_NAMES['sso_settings'];
	}

	/**
	 * Delete the data for the Role Mapping Advanced Settings tab.
	 *
	 * @return void
	 */
	public function delete_data() {
		$selected_idp = Utility::sanitize_post_data( 'selected_idp_name' );
		if ( empty( $selected_idp ) ) {
			return;
		}

		foreach ( array_keys( get_object_vars( $this ) ) as $option_name ) {
			DB_Utils::delete_records(
				$this->get_table_name(),
				array(
					'idp_id'      => $selected_idp,
					'option_name' => $option_name,
					'subsite_id'  => Utility::get_subsite_id_for_environment(),
				)
			);
		}

		DB_Utils::delete_records(
			$this->get_table_name(),
			array(
				'option_name' => 'attr_role_advanced_settings_recorded',
				'idp_id'      => $selected_idp,
				'subsite_id'  => Utility::get_subsite_id_for_environment(),
			)
		);
		Error_Success_Message::show_admin_notice( 'Advanced settings reset successfully.', 'SUCCESS' );
	}

	/**
	 * Save the data for the Role Mapping Advanced Settings tab.
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

		$advanced_settings_data_properties = get_object_vars( $this );
		foreach ( $advanced_settings_data_properties as $option_name => $option_value ) {
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
				'option_name'  => 'attr_role_advanced_settings_recorded',
				'option_value' => true,
				'idp_id'       => $selected_idp,
				'subsite_id'   => get_current_blog_id(),
			),
			array(
				'option_name' => 'attr_role_advanced_settings_recorded',
				'idp_id'      => $selected_idp,
				'subsite_id'  => get_current_blog_id(),
			)
		);
	}
}
