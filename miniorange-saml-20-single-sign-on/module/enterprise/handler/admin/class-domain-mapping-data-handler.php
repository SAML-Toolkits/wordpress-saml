<?php
/**
 * Domain Mapping Data Handler - Enterprise Module
 *
 * Extends the premium domain mapping data handler to provide enterprise module functionality.
 *
 * PHP Compatibility: 5.6+
 *
 * @package miniorange-saml-20-single-sign-on
 */

namespace MOSAML\Module\Enterprise\Handler\Admin;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\Module\Premium\Handler\Admin\Domain_Mapping_Data_Handler as Premium_Domain_Mapping_Data_Handler;
use MOSAML\SRC\Interfaces\Form_Data_Handler_Interface;
use MOSAML\SRC\Utils\DB_Utils;
use MOSAML\SRC\Utils\Error_Success_Message;
use MOSAML\SRC\Utils\Utility;
use MOSAML\SRC\Constant\Constants;

/**
 * Domain Mapping Data Handler.
 */
class Domain_Mapping_Data_Handler extends Premium_Domain_Mapping_Data_Handler implements Form_Data_Handler_Interface {

	/**
	 * Validate and save the domain mapping configuration.
	 *
	 * @return void
	 */
	public function validate_and_save_data() {
		$this->enable_domain_mapping = Utility::sanitize_post_data( 'mo_saml_enable_domain_mapping' );

		$selected_environment_id   = DB_Utils::get_environment_details( 'id', false );
		$blog_id_for_environment = Utility::get_subsite_id_for_environment( $selected_environment_id );
		$idp_id                    = DB_Utils::get_default_inserted_idp_details( 'id', $selected_environment_id );
		DB_Utils::insert_or_update(
			$this->get_table_name(),
			array(
				'option_name'  => 'enable_domain_mapping',
				'option_value' => $this->enable_domain_mapping,
				'subsite_id'   => $blog_id_for_environment,
				'idp_id'       => $idp_id,
			),
			array(
				'option_name' => 'enable_domain_mapping',
				'subsite_id'  => $blog_id_for_environment,
				'idp_id'      => $idp_id,
			)
		);
		if ( 'checked' === $this->enable_domain_mapping ) {
			$this->domain_mapping_fail_option = Utility::sanitize_post_data( 'domain_login_failed_option' );
			DB_Utils::insert_or_update(
				$this->get_table_name(),
				array(
					'option_name'  => 'domain_mapping_fail_option',
					'option_value' => $this->domain_mapping_fail_option,
					'subsite_id'   => $blog_id_for_environment,
					'idp_id'       => $idp_id,
				),
				array(
					'option_name' => 'domain_mapping_fail_option',
					'subsite_id'  => $blog_id_for_environment,
					'idp_id'      => $idp_id,
				)
			);
			$configured_idps = DB_Utils::get_records( Constants::DATABASE_TABLE_NAMES['idp_details'], array( 'environment_id' => DB_Utils::get_environment_details( 'id', false ) ) );
			foreach ( $configured_idps as $idp ) {
				$this->domain_mapping_config[ $idp->idp_id ] = Utility::sanitize_post_data( 'saml_domain_mapping_' . $idp->idp_id );
				if ( ! preg_match( '/^\S*$/', $this->domain_mapping_config[ $idp->idp_id ] ) ) {
					Error_Success_Message::show_admin_notice( 'Spaces are not allowed in the domain values.' );
					return;
				}
			}
			DB_Utils::insert_or_update(
				$this->get_table_name(),
				array(
					'option_name'  => 'domain_mapping_config',
					'option_value' => $this->domain_mapping_config,
					'subsite_id'   => $blog_id_for_environment,
					'idp_id'       => $idp_id,
				),
				array(
					'option_name' => 'domain_mapping_config',
					'subsite_id'  => $blog_id_for_environment,
					'idp_id'      => $idp_id,
				)
			);
		}
		Error_Success_Message::show_admin_notice( 'Domain Mapping details saved successfully.', 'SUCCESS' );
	}

	/**
	 * Get the domain mapping configuration.
	 *
	 * @param array $where The where clause to filter the data.
	 * @return object
	 */
	public function get_data( $where = array() ) {
		$domain_mapping_where = array_merge(
			array(
				'option_name' => 'enable_domain_mapping',
				'subsite_id'  => Utility::get_subsite_id_for_environment(),
			),
			$where
		);

		$record = DB_Utils::get_records(
			$this->get_table_name(),
			$domain_mapping_where,
			true
		);
		if ( $record ) {
			$this->enable_domain_mapping = $record->option_value;
		}

		$domain_mapping_fail_option_where = array_merge(
			array(
				'option_name' => 'domain_mapping_fail_option',
				'subsite_id'  => Utility::get_subsite_id_for_environment(),
			),
			$where
		);

		$record = DB_Utils::get_records(
			$this->get_table_name(),
			$domain_mapping_fail_option_where,
			true
		);
		if ( $record ) {
			$this->domain_mapping_fail_option = $record->option_value;
		}

		$domain_mapping_config_where = array_merge(
			array(
				'option_name' => 'domain_mapping_config',
				'subsite_id'  => Utility::get_subsite_id_for_environment(),
			),
			$where
		);

		$record = DB_Utils::get_records(
			$this->get_table_name(),
			$domain_mapping_config_where,
			true
		);
		if ( $record ) {
			$this->domain_mapping_config = maybe_unserialize( $record->option_value );
		}

		return parent::get_data( $where );
	}
}
