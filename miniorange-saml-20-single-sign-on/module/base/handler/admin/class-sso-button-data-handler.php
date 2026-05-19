<?php
/**
 * SSO Button Data Handler - Base Module
 *
 * Handles data operations for SSO button configuration in the base module.
 *
 * PHP Compatibility: 5.6+
 *
 * @package miniorange-saml-20-single-sign-on
 * @subpackage Module\Base\Handler\Admin
 */

namespace MOSAML\Module\Base\Handler\Admin;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\SRC\Utils\Utility;
use MOSAML\SRC\Utils\DB_Utils;
use MOSAML\SRC\Utils\Error_Success_Message;
use MOSAML\SRC\Interfaces\Form_Data_Handler_Interface;
use MOSAML\SRC\Constant\Constants;

/**
 * SSO Button Data Handler.
 */
class SSO_Button_Data_Handler implements Form_Data_Handler_Interface {

	/**
	 * Enable SSO button.
	 *
	 * @var string
	 */
	public $enable_sso_button = 'checked';

	/**
	 * Use button as shortcode.
	 *
	 * @var string
	 */
	public $use_button_as_shortcode;

	/**
	 * Use button as widget.
	 *
	 * @var string
	 */
	public $use_button_as_widget;

	/**
	 * SSO button configuration array.
	 *
	 * @var array
	 */
	public $sso_button_config = array(
		'button_type'     => 'longbutton',
		'button_size'     => '50',
		'button_width'    => '270',
		'button_height'   => '30',
		'button_curve'    => '3',
		'button_color'    => '#2271b1',
		'font_size'       => '14',
		'font_color'      => '#ffffff',
		'button_position' => 'above',
	);

	/**
	 * Get the table name for this DTO.
	 *
	 * @return string
	 */
	public function get_table_name() {
		return Constants::DATABASE_TABLE_NAMES['sso_settings'];
	}

	/**
	 * Validate and save the SSO button configuration.
	 *
	 * @return void
	 */
	public function validate_and_save_data() {
		$idp_id                  = Utility::sanitize_post_data( 'sso_link_idp' );
		$this->enable_sso_button = Utility::sanitize_post_data( 'mo_saml_add_sso_button_wp' );

		$idp_details                       = DB_Utils::get_records( Constants::DATABASE_TABLE_NAMES['idp_details'], array( 'id' => $idp_id ), true );
		$this->sso_button_config['idp_id'] = $idp_details->idp_id;

		foreach ( get_object_vars( $this ) as $key => $value ) {
			if ( null === $value ) {
				continue;
			}

			$table_data   = array(
				'option_name'  => $key,
				'option_value' => $value,
				'idp_id'       => $idp_id,
				'subsite_id'   => Utility::get_subsite_id_for_environment(),
			);
			$query_result = DB_Utils::insert_or_update(
				$this->get_table_name(),
				$table_data,
				array(
					'option_name' => $key,
					'idp_id'      => $idp_id,
					'subsite_id'  => Utility::get_subsite_id_for_environment(),
				)
			);
		}

		Error_Success_Message::show_admin_notice( 'Login button updated successfully.', 'SUCCESS' );
	}

	/**
	 * Get the SSO button configuration.
	 *
	 * @param array $where The where clause to filter the data.
	 * @return object The data.
	 */
	public function get_data( $where = array() ) {
		if ( Utility::is_legacy_data_fallback_required() ) {
			return apply_filters( 'mosaml_legacy_data_fallback_object', $this, $where );
		}
		$where   = array_merge(
			array( 'option_name' => array_keys( get_object_vars( $this ) ) ),
			$where
		);

		$records = DB_Utils::get_records( $this->get_table_name(), $where );
		if ( $records ) {
			foreach ( $records as $record ) {
				$this->{ $record->option_name } = maybe_unserialize( $record->option_value );
			}
		}

		if ( ! isset( $this->sso_button_config['button_text'] ) ) {
			if(! isset($where['idp_id'])) {
				$where['idp_id'] = $this->sso_button_config['idp_id'];
			}
			$idp_details = DB_Utils::get_records( Constants::DATABASE_TABLE_NAMES['idp_details'], array( 'id' => $where['idp_id'] ), true );
			if ( ! empty( $idp_details ) ) {
				$this->sso_button_config['button_text'] = 'Login with ' . $idp_details->idp_name;
				$this->sso_button_config['idp_id']      = $idp_details->idp_id;
			}
		}

		if ( ! empty( $this->use_button_as_shortcode ) && ! isset( $this->sso_button_config['use_button_as_shortcode'] ) ) {
			$this->sso_button_config['use_button_as_shortcode'] = $this->use_button_as_shortcode;
		}
		if ( ! empty( $this->use_button_as_widget ) && ! isset( $this->sso_button_config['use_button_as_widget'] ) ) {
			$this->sso_button_config['use_button_as_widget'] = $this->use_button_as_widget;
		}

		return $this;
	}

	/**
	 * Delete the SSO button configuration.
	 *
	 * @return void
	 */
	public function delete_data() {
		$selected_idp = Utility::sanitize_post_data( 'sso_link_idp' );
		DB_Utils::delete_records(
			$this->get_table_name(),
			array(
				'idp_id'      => $selected_idp,
				'subsite_id'  => Utility::get_subsite_id_for_environment(),
				'option_name' => 'sso_button_config',
			)
		);
		Error_Success_Message::show_admin_notice( 'Login button reset successfully.', 'SUCCESS' );
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
			$checkbox_options = array( 'enable_sso_button', 'use_button_as_shortcode', 'use_button_as_widget' );
			if ( in_array( $option_name, $checkbox_options, true ) && null === $option_value ) {
				$option_value = '';
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
