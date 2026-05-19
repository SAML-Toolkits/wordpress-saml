<?php
/**
 * Legacy Options Configuration - STANDARD VERSION.
 *
 * @package    MOSAML
 * @subpackage MOSAML/src/handler/import-export/version-mappings
 */

namespace MOSAML\SRC\Handler\Import_Export\Version_Mappings;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Legacy Options Enum - Standard.
 */
class Legacy_Options_Enum_Standard {

	const CLASS_IMPORT_ORDER = array(
		'SP_Setup_Data',
		'SP_Endpoints_Data',
		'Attribute_Mapping_Data',
		'Role_Assignment_Settings_Data',
		'Relay_State_Data',
		'Site_Auto_Redirection_Data',
		'Force_Authentication_Data',
		'RSS_Feed_Access_Data',
		'Login_Page_Auto_Redirection_Data',
		'Backdoor_Url_Login_Data',
		'SSO_Button_Data',
		'Shortcode_Widget_Data',
	);

	const CONFIG_KEY_TO_COMMON_MAP = array(
		'relay_state'                      => array(
			'class'     => 'Relay_State_Data',
			'property'  => 'login_relay_state',
			'transform' => null,
		),
		'redirect_idp'                     => array(
			'class'     => 'Site_Auto_Redirection_Data',
			'property'  => 'enable_site_auto_redirect',
			'transform' => 'true_to_checked',
		),
		'force_authentication'             => array(
			'class'     => 'Force_Authentication_Data',
			'property'  => 'enable_force_authentication',
			'transform' => null,
		),
		'enable_access_rss'                => array(
			'class'     => 'RSS_Feed_Access_Data',
			'property'  => 'enable_rss_feed_access',
			'transform' => 'true_to_checked',
		),
		'auto_redirect'                    => array(
			'class'     => 'Login_Page_Auto_Redirection_Data',
			'property'  => 'redirect_from_wp_login',
			'transform' => 'true_to_checked',
		),
		'allow_wp_signin'                  => array(
			'class'     => 'Backdoor_Url_Login_Data',
			'property'  => 'enable_backdoor_url_login',
			'transform' => 'true_to_checked',
		),
		'custom_login_button'              => array(
			'class'     => 'Shortcode_Widget_Data',
			'property'  => 'widget_config',
			'transform' => 'add_to_widget_config',
		),
		'custom_greeting_text'             => array(
			'class'     => 'Shortcode_Widget_Data',
			'property'  => 'widget_config',
			'transform' => 'add_to_widget_config',
		),
		'custom_greeting_name'             => array(
			'class'     => 'Shortcode_Widget_Data',
			'property'  => 'widget_config',
			'transform' => 'add_to_widget_config',
		),
		'custom_logout_button'             => array(
			'class'     => 'Shortcode_Widget_Data',
			'property'  => 'widget_config',
			'transform' => 'add_to_widget_config',
		),
		'backdoor_url'                     => array(
			'class'     => 'Backdoor_Url_Login_Data',
			'property'  => 'backdoor_url',
			'transform' => null,
		),
		'saml_login_widget'                => array(
			'class'     => '',
			'property'  => '',
			'transform' => null,
			'anomaly'   => 'save_wp_widget_config',
		),
		'sso_button'                       => array(
			'class'     => 'SSO_Button_Data',
			'property'  => 'enable_sso_button',
			'transform' => 'true_to_checked',
		),
		'keep_configuration_intact'        => array(
			'class'     => '',
			'property'  => '',
			'transform' => null,
		),
		'sp_base_url'                      => array(
			'class'     => 'SP_Endpoints_Data',
			'property'  => 'sp_base_url',
			'transform' => null,
		),
		'sp_entity_id'                     => array(
			'class'     => 'SP_Endpoints_Data',
			'property'  => 'sp_entity_id',
			'transform' => null,
		),
		'identity_name'                    => array(
			'class'     => 'SP_Setup_Data',
			'property'  => 'idp_name',
			'transform' => null,
			'anomaly'   => 'set_idp_fields',
		),
		'login_binding_type'               => array(
			'class'     => 'SP_Setup_Data',
			'property'  => 'sso_binding',
			'transform' => null,
		),
		'login_url'                        => array(
			'class'     => 'SP_Setup_Data',
			'property'  => 'sso_url',
			'transform' => null,
		),
		'issuer'                           => array(
			'class'     => 'SP_Setup_Data',
			'property'  => 'entity_id',
			'transform' => null,
		),
		'x509_certificate'                 => array(
			'class'     => 'SP_Setup_Data',
			'property'  => 'idp_certificate',
			'transform' => null,
		),
		'request_signed'                   => array(
			'class'     => 'SP_Setup_Data',
			'property'  => 'sign_sso_slo_request',
			'transform' => null,
		),
		'nameid_format'                    => array(
			'class'     => 'SP_Setup_Data',
			'property'  => 'name_id_format',
			'transform' => 'prepare_name_id_format',
		),
		'is_encoding_enabled'              => array(
			'class'     => 'SP_Setup_Data',
			'property'  => 'character_encoding',
			'transform' => null,
		),
		'attribute_username'               => array(
			'class'     => 'Attribute_Mapping_Data',
			'property'  => 'user_name',
			'transform' => null,
		),
		'attribute_email'                  => array(
			'class'     => 'Attribute_Mapping_Data',
			'property'  => 'email',
			'transform' => null,
		),
		'attribute_first_name'             => array(
			'class'     => 'Attribute_Mapping_Data',
			'property'  => 'first_name',
			'transform' => null,
		),
		'attribute_last_name'              => array(
			'class'     => 'Attribute_Mapping_Data',
			'property'  => 'last_name',
			'transform' => null,
		),
		'attribute_display_name'           => array(
			'class'     => 'Attribute_Mapping_Data',
			'property'  => 'display_name',
			'transform' => null,
		),
		'role_do_not_update_existing_user' => array(
			'class'     => 'Role_Assignment_Settings_Data',
			'property'  => 'update_existing_user',
			'transform' => 'invert_checked',
		),
		'role_default_role'                => array(
			'class'     => 'Role_Assignment_Settings_Data',
			'property'  => 'default_role_new',
			'transform' => 'validate_wp_role',
			'anomaly'   => 'set_default_role_existing',
		),
		'test_config_attrs'                => array(
			'class'     => 'SP_Setup_Data',
			'property'  => 'test_config_attributes',
			'transform' => null,
		),
	);
}
