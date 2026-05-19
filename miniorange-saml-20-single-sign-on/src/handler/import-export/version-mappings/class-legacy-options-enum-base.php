<?php
/**
 * Legacy Options Configuration - BASE VERSION.
 *
 * @package    MOSAML
 * @subpackage MOSAML/src/handler/import-export/version-mappings
 */

namespace MOSAML\SRC\Handler\Import_Export\Version_Mappings;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Legacy Options Enum - Base.
 */
class Legacy_Options_Enum_Base {

	const CLASS_IMPORT_ORDER = array(
		'SP_Setup_Data',
		'SP_Endpoints_Data',
		'Role_Assignment_Settings_Data',
		'SSO_Button_Data',
		'Shortcode_Widget_Data',
	);

	const CONFIG_KEY_TO_COMMON_MAP = array(
		'sso_button'                => array(
			'class'     => 'SSO_Button_Data',
			'property'  => 'enable_sso_button',
			'transform' => 'true_to_checked',
		),
		'keep_configuration_intact' => array(
			'class'     => 'Keep_Settings_Data',
			'property'  => '',
			'transform' => null,
		),
		'sp_base_url'               => array(
			'class'     => 'SP_Endpoints_Data',
			'property'  => 'sp_base_url',
			'transform' => null,
		),
		'sp_entity_id'              => array(
			'class'     => 'SP_Endpoints_Data',
			'property'  => 'sp_entity_id',
			'transform' => null,
		),
		'identity_name'             => array(
			'class'     => 'SP_Setup_Data',
			'property'  => 'idp_name',
			'transform' => null,
			'anomaly'   => 'set_idp_fields',
		),
		'login_url'                 => array(
			'class'     => 'SP_Setup_Data',
			'property'  => 'sso_url',
			'transform' => null,
		),
		'issuer'                    => array(
			'class'     => 'SP_Setup_Data',
			'property'  => 'entity_id',
			'transform' => null,
		),
		'x509_certificate'          => array(
			'class'     => 'SP_Setup_Data',
			'property'  => 'idp_certificate',
			'transform' => null,
		),
		'is_encoding_enabled'       => array(
			'class'     => 'SP_Setup_Data',
			'property'  => 'character_encoding',
			'transform' => null,
		),
		'role_default_role'         => array(
			'class'     => 'Role_Assignment_Settings_Data',
			'property'  => 'default_role_new',
			'transform' => 'validate_wp_role',
			'anomaly'   => 'set_default_role_existing',
		),
		'test_config_attrs'         => array(
			'class'     => 'SP_Setup_Data',
			'property'  => 'test_config_attributes',
			'transform' => null,
		),
	);
}
