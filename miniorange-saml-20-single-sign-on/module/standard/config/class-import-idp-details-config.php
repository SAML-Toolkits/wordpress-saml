<?php
/**
 * Standard Module - Import IDP Details Configuration Class
 *
 * Handles IDP details configuration data import for the standard module.
 *
 * @package MOSAML\Module\Standard\Config
 * @since 1.0.0
 */

namespace MOSAML\Module\Standard\Config;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\Module\Base\Config\Import_Idp_Details_Config as Base_Import_Idp_Details_Config;

/**
 * Standard Import IDP Details Configuration Class
 */
class Import_Idp_Details_Config extends Base_Import_Idp_Details_Config {

	/**
	 * Import configuration data (Standard module - extends Base)
	 *
	 * @param array $config_data Full configuration data.
	 * @param array $idp_info IDP information.
	 */
	public function import_config( $config_data, $idp_info ) {
		parent::import_config( $config_data, $idp_info );

		$this->map_standard_idp_data( $config_data );
		$this->save_standard_data();
	}

	/**
	 * Map standard module specific IDP data
	 *
	 * @param array $config_data Configuration data.
	 */
	protected function map_standard_idp_data( $config_data ) {
		$identity_data = isset( $config_data['Identity_Provider'] ) ? $config_data['Identity_Provider'] : array();
		$service_data  = isset( $config_data['Service_Provider'] ) ? $config_data['Service_Provider'] : array();
		$all_data      = array_merge( $identity_data, $service_data );

		$standard_mapping = array(
			'SP_Base_Url'         => 'sp_entity_id',
			'Identity_name'       => 'idp_name',
			'Login_binding_type'  => 'sso_binding',
			'NameID_Format'       => 'name_id_format',
			'Request_signed'      => 'sign_sso_slo_request',
			'Is_encoding_enabled' => 'character_encoding',
		);

		foreach ( $standard_mapping as $json_key => $class_var ) {
			if ( isset( $all_data[ $json_key ] ) ) {
				$value = $all_data[ $json_key ];
				if ( is_array( $value ) && isset( $value[0] ) ) {
					$value = $value[0];
				}
				$this->$class_var = $value;
			}
		}
	}

	/**
	 * Save standard-specific configuration data.
	 *
	 * @return void
	 */
	protected function save_standard_data() {
		$standard_data = array(
			'sso_binding'          => $this->sso_binding,
			'name_id_format'       => $this->name_id_format,
			'sign_sso_slo_request' => $this->sign_sso_slo_request,
			'character_encoding'   => $this->character_encoding,
		);

		$this->save_idp_data( $standard_data );
	}
}
