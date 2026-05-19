<?php
/**
 * Base Relay State Data Handler.
 *
 * @package miniorange-saml-20-single-sign-on/module/base/handler/admin
 */

namespace MOSAML\Module\Base\Handler\Admin;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\SRC\Interfaces\Form_Data_Handler_Interface;
use MOSAML\SRC\Constant\Constants;
use MOSAML\SRC\Utils\DB_Utils;
use MOSAML\SRC\Utils\Utility;

/**
 * Base Relay State Data Handler.
 */
class Relay_State_Data_Handler implements Form_Data_Handler_Interface {

	/**
	 * Allow third party relay state.
	 *
	 * @var string
	 */
	public $allow_third_party_relay_state = '';

	/**
	 * Login relay state.
	 *
	 * @var string
	 */
	public $login_relay_state;

	/**
	 * Logout relay state.
	 *
	 * @var string
	 */
	public $logout_relay_state;

	/**
	 * Get the table name.
	 *
	 * @return string
	 */
	public function get_table_name() {
		return Constants::DATABASE_TABLE_NAMES['sso_settings'];
	}

	/**
	 * Validate and save the data.
	 *
	 * @return void
	 */
	public function validate_and_save_data() {}

	/**
	 * Get the data.
	 *
	 * @param array $where The where clause to filter the data.
	 * @return object The data.
	 */
	public function get_data( $where = array() ) {
		return $this;
	}

	/**
	 * Save the data.
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
	}
}
