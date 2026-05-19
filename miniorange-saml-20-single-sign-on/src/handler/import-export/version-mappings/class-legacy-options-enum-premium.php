<?php
/**
 * Legacy Options Configuration - PREMIUM VERSION.
 *
 * @package    MOSAML
 * @subpackage MOSAML/src/handler/import-export/version-mappings
 */

namespace MOSAML\SRC\Handler\Import_Export\Version_Mappings;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Legacy Options Enum - Premium.
 */
class Legacy_Options_Enum_Premium {

	const CLASS_IMPORT_ORDER = array(
		'SP_Setup_Data',
		'SP_Endpoints_Data',
		'Attribute_Mapping_Data',
		'Role_Mapping_Data',
		'Role_Assignment_Settings_Data',
		'Role_Mapping_Advanced_Settings_Data',
		'Relay_State_Data',
		'Site_Auto_Redirection_Data',
		'Force_Authentication_Data',
		'RSS_Feed_Access_Data',
		'Login_Page_Auto_Redirection_Data',
		'Backdoor_Url_Login_Data',
		'Certificate_Data',
		'Custom_Messages_Data',
		'Metadata_Sync_Data',
		'SSO_User_Data',
		'SSO_Button_Data',
		'Shortcode_Widget_Data',
	);

	const CONFIG_KEY_TO_COMMON_MAP = array(
		'relay_state'                              => array(
			'class'     => 'Relay_State_Data',
			'property'  => 'login_relay_state',
			'transform' => null,
		),
		'absolute_relay_state'                     => array(
			'class'     => 'Relay_State_Data',
			'property'  => 'allow_third_party_relay_state',
			'transform' => 'true_to_checked',
		),
		'logout_relay_state'                       => array(
			'class'     => 'Relay_State_Data',
			'property'  => 'logout_relay_state',
			'transform' => null,
			'anomaly'   => 'handle_relay_states',
		),
		'redirect_idp'                             => array(
			'class'     => 'Site_Auto_Redirection_Data',
			'property'  => 'site_auto_redirection_option',
			'transform' => 'true_to_default_idp',
			'anomaly'   => 'set_enable_site_auto_redirect',
		),
		'force_authentication'                     => array(
			'class'     => 'Force_Authentication_Data',
			'property'  => 'enable_force_authentication',
			'transform' => null,
		),
		'enable_access_rss'                        => array(
			'class'     => 'RSS_Feed_Access_Data',
			'property'  => 'enable_rss_feed_access',
			'transform' => 'true_to_checked',
		),
		'auto_redirect'                            => array(
			'class'     => 'Login_Page_Auto_Redirection_Data',
			'property'  => 'redirect_from_wp_login',
			'transform' => 'true_to_checked',
		),
		'allow_wp_signin'                          => array(
			'class'     => 'Backdoor_Url_Login_Data',
			'property'  => 'enable_backdoor_url_login',
			'transform' => 'true_to_checked',
		),
		'custom_login_button'                      => array(
			'class'     => 'Shortcode_Widget_Data',
			'property'  => 'widget_config',
			'transform' => 'add_to_widget_config',
		),
		'custom_greeting_text'                     => array(
			'class'     => 'Shortcode_Widget_Data',
			'property'  => 'widget_config',
			'transform' => 'add_to_widget_config',
		),
		'custom_greeting_name'                     => array(
			'class'     => 'Shortcode_Widget_Data',
			'property'  => 'widget_config',
			'transform' => 'add_to_widget_config',
		),
		'custom_logout_button'                     => array(
			'class'     => 'Shortcode_Widget_Data',
			'property'  => 'widget_config',
			'transform' => 'add_to_widget_config',
		),
		'backdoor_url'                             => array(
			'class'     => 'Backdoor_Url_Login_Data',
			'property'  => 'backdoor_url',
			'transform' => null,
		),
		'redirect_to_wp_login'                     => array(
			'class'     => 'Site_Auto_Redirection_Data',
			'property'  => 'site_auto_redirection_option',
			'transform' => 'true_to_wp_login',
			'anomaly'   => 'set_enable_site_auto_redirect',
		),
		'add_sso_button'                           => array(
			'class'     => 'SSO_Button_Data',
			'property'  => 'enable_sso_button',
			'transform' => 'true_to_checked',
		),
		'use_button_as_shortcode'                  => array(
			'class'     => 'SSO_Button_Data',
			'property'  => 'use_button_as_shortcode',
			'transform' => 'true_to_checked',
		),
		'use_button_as_widget'                     => array(
			'class'     => 'SSO_Button_Data',
			'property'  => 'use_button_as_widget',
			'transform' => 'true_to_checked',
		),
		'sso_button_size'                          => array(
			'class'     => 'SSO_Button_Data',
			'property'  => 'sso_button_config',
			'transform' => 'button_attributes',
		),
		'sso_button_width'                         => array(
			'class'     => 'SSO_Button_Data',
			'property'  => 'sso_button_config',
			'transform' => 'button_attributes',
		),
		'sso_button_height'                        => array(
			'class'     => 'SSO_Button_Data',
			'property'  => 'sso_button_config',
			'transform' => 'button_attributes',
		),
		'sso_button_curve'                         => array(
			'class'     => 'SSO_Button_Data',
			'property'  => 'sso_button_config',
			'transform' => 'button_attributes',
		),
		'sso_button_color'                         => array(
			'class'     => 'SSO_Button_Data',
			'property'  => 'sso_button_config',
			'transform' => 'button_attributes',
		),
		'sso_button_text'                          => array(
			'class'     => 'SSO_Button_Data',
			'property'  => 'sso_button_config',
			'transform' => 'button_attributes',
		),
		'sso_button_theme'                         => array(
			'class'     => 'SSO_Button_Data',
			'property'  => 'sso_button_config',
			'transform' => 'button_attributes',
		),
		'sso_button_font_color'                    => array(
			'class'     => 'SSO_Button_Data',
			'property'  => 'sso_button_config',
			'transform' => 'button_font_attributes',
		),
		'sso_button_font_size'                     => array(
			'class'     => 'SSO_Button_Data',
			'property'  => 'sso_button_config',
			'transform' => 'button_font_attributes',
		),
		'sso_button_position'                      => array(
			'class'     => 'SSO_Button_Data',
			'property'  => 'sso_button_config',
			'transform' => 'button_attributes',
		),
		'saml_login_widget'                        => array(
			'class'     => '',
			'property'  => '',
			'transform' => null,
			'anomaly'   => 'save_wp_widget_config',
		),
		'keep_configuration_intact'                => array(
			'class'     => '',
			'property'  => '',
			'transform' => null,
		),
		'sp_base_url'                              => array(
			'class'     => 'SP_Endpoints_Data',
			'property'  => 'sp_base_url',
			'transform' => 'empty_to_default',
		),
		'sp_entity_id'                             => array(
			'class'     => 'SP_Endpoints_Data',
			'property'  => 'sp_entity_id',
			'transform' => 'empty_to_default',
		),
		'identity_name'                            => array(
			'class'     => 'SP_Setup_Data',
			'property'  => 'idp_name',
			'transform' => null,
			'anomaly'   => 'set_idp_fields',
		),
		'assertion_signed'                         => array(
			'class'     => 'SP_Setup_Data',
			'property'  => '',
			'transform' => null,
		),
		'login_binding_type'                       => array(
			'class'     => 'SP_Setup_Data',
			'property'  => 'sso_binding',
			'transform' => null,
		),
		'login_url'                                => array(
			'class'     => 'SP_Setup_Data',
			'property'  => 'sso_url',
			'transform' => null,
		),
		'logout_binding_type'                      => array(
			'class'     => 'SP_Setup_Data',
			'property'  => 'slo_binding',
			'transform' => null,
		),
		'logout_url'                               => array(
			'class'     => 'SP_Setup_Data',
			'property'  => 'slo_url',
			'transform' => null,
		),
		'issuer'                                   => array(
			'class'     => 'SP_Setup_Data',
			'property'  => 'entity_id',
			'transform' => null,
		),
		'x509_certificate'                         => array(
			'class'     => 'SP_Setup_Data',
			'property'  => 'idp_certificate',
			'transform' => null,
		),
		'request_signed'                           => array(
			'class'     => 'SP_Setup_Data',
			'property'  => 'sign_sso_slo_request',
			'transform' => null,
		),
		'nameid_format'                            => array(
			'class'     => 'SP_Setup_Data',
			'property'  => 'name_id_format',
			'transform' => 'prepare_name_id_format',
		),
		'is_encoding_enabled'                      => array(
			'class'     => 'SP_Setup_Data',
			'property'  => 'character_encoding',
			'transform' => 'true_to_checked',
		),
		'identity_name_for_sync'                   => array(
			'class'     => 'SP_Setup_Data',
			'property'  => '',
			'transform' => null,
		),
		'assertion_time_validation'                => array(
			'class'     => 'SP_Setup_Data',
			'property'  => 'assertion_time_validity',
			'transform' => null,
		),
		'idp_status'                               => array(
			'class'     => 'SP_Setup_Data',
			'property'  => 'status',
			'transform' => null,
		),
		'attribute_username'                       => array(
			'class'     => 'Attribute_Mapping_Data',
			'property'  => 'user_name',
			'transform' => null,
		),
		'attribute_email'                          => array(
			'class'     => 'Attribute_Mapping_Data',
			'property'  => 'email',
			'transform' => null,
		),
		'attribute_first_name'                     => array(
			'class'     => 'Attribute_Mapping_Data',
			'property'  => 'first_name',
			'transform' => null,
		),
		'attribute_last_name'                      => array(
			'class'     => 'Attribute_Mapping_Data',
			'property'  => 'last_name',
			'transform' => null,
		),
		'attribute_nickname'                       => array(
			'class'     => 'Attribute_Mapping_Data',
			'property'  => 'nick_name',
			'transform' => null,
		),
		'attribute_display_name'                   => array(
			'class'     => 'Attribute_Mapping_Data',
			'property'  => 'display_name',
			'transform' => null,
		),
		'attribute_custom_mapping'                 => array(
			'class'     => 'Attribute_Mapping_Data',
			'property'  => 'custom_attributes',
			'transform' => 'format_custom_attributes',
		),
		'attribute_show_in_user_menu'              => array(
			'class'     => 'Attribute_Mapping_Data',
			'property'  => 'custom_attributes',
			'transform' => 'format_custom_attributes_display',
		),
		'attribute_update_display_name'            => array(
			'class'     => 'Attribute_Mapping_Data',
			'property'  => 'do_not_update_display_name',
			'transform' => 'true_to_checked',
		),
		'attribute_group_name'                     => array(
			'class'     => 'Role_Assignment_Settings_Data',
			'property'  => 'group_attribute_name',
			'transform' => null,
		),
		'email_domains'                            => array(
			'class'     => 'Role_Mapping_Advanced_Settings_Data',
			'property'  => 'allow_deny_user_domain_value',
			'transform' => null,
		),
		'enable_domain_restriction_login'          => array(
			'class'     => 'Role_Mapping_Advanced_Settings_Data',
			'property'  => 'allow_deny_user_domain_toggle',
			'transform' => null,
		),
		'allow_deny_user_with_domain'              => array(
			'class'     => 'Role_Mapping_Advanced_Settings_Data',
			'property'  => 'allow_deny_user_domain_type',
			'transform' => null,
		),
		'role_action_for_role_not_configured'      => array(
			'class'     => '',
			'property'  => '',
			'transform' => null,
		),
		'role_update_admin_user_role'              => array(
			'class'     => 'Role_Assignment_Settings_Data',
			'property'  => 'apply_role_mapping_to_admin',
			'transform' => null,
		),
		'role_default_role'                        => array(
			'class'     => 'Role_Assignment_Settings_Data',
			'property'  => 'default_role_new',
			'transform' => 'validate_wp_role',
			'anomaly'   => 'set_default_role_existing',
		),
		'role_mapping'                             => array(
			'class'     => 'Role_Mapping_Data',
			'property'  => 'role_mapping_values',
			'transform' => null,
		),
		'role_do_not_assign_role_unlisted'         => array(
			'class'     => 'Role_Assignment_Settings_Data',
			'property'  => '',
			'transform' => null,
			'anomaly'   => 'handle_none_role',
		),
		'assign_default_role'                      => array(
			'class'     => 'Role_Assignment_Settings_Data',
			'property'  => '',
			'transform' => null,
			'anomaly'   => 'handle_default_role',
		),
		'role_do_not_auto_create_users'            => array(
			'class'     => 'Role_Assignment_Settings_Data',
			'property'  => 'create_new_user',
			'transform' => 'invert_checked',
		),
		'role_do_not_update_existing_user'         => array(
			'class'     => 'Role_Mapping_Advanced_Settings_Data',
			'property'  => 'do_not_update_existing_user_roles',
			'transform' => null,
		),
		'role_do_not_login_with_roles'             => array(
			'class'     => 'Role_Mapping_Advanced_Settings_Data',
			'property'  => 'allow_deny_idp_attribute_toggle',
			'transform' => null,
		),
		'role_restrict_users_with_groups'          => array(
			'class'     => 'Role_Mapping_Advanced_Settings_Data',
			'property'  => 'attribute_restriction_value',
			'transform' => null,
		),
		'attribute_restriction'                    => array(
			'class'     => 'Role_Mapping_Advanced_Settings_Data',
			'property'  => 'attribute_restriction_group',
			'transform' => null,
		),
		'attribute_restriction_allow_deny'         => array(
			'class'     => 'Role_Mapping_Advanced_Settings_Data',
			'property'  => 'allow_deny_idp_attribute',
			'transform' => null,
		),
		'dont_create_new_user'                     => array(
			'class'     => 'Role_Mapping_Advanced_Settings_Data',
			'property'  => 'do_not_create_new_users',
			'transform' => null,
		),
		'role_enable_regex'                        => array(
			'class'     => 'Role_Mapping_Advanced_Settings_Data',
			'property'  => 'enable_regex_for_role_mapping',
			'transform' => null,
		),
		'whitelist_existing_users_role'            => array(
			'class'     => 'Role_Mapping_Advanced_Settings_Data',
			'property'  => 'whitelist_existing_users_roles',
			'transform' => null,
		),
		'selected_whitelisted_roles'               => array(
			'class'     => 'Role_Mapping_Advanced_Settings_Data',
			'property'  => 'whitelisted_roles',
			'transform' => null,
		),
		'test_config_error_log'                    => array(
			'class'     => '',
			'property'  => '',
			'transform' => null,
		),
		'test_config_attibutes'                    => array(
			'class'     => 'SP_Setup_Data',
			'property'  => 'test_config_attributes',
			'transform' => null,
		),
		'custom_public_certificate'                => array(
			'class'     => 'Certificate_Data',
			'property'  => 'public_key',
			'transform' => null,
		),
		'custom_private_certificate'               => array(
			'class'     => 'Certificate_Data',
			'property'  => 'private_key',
			'transform' => null,
		),
		'enable_public_certificate'                => array(
			'class'     => '',
			'property'  => '',
			'transform' => null,
		),
		'custom_account_creation_disabled_message' => array(
			'class'     => 'Custom_Messages_Data',
			'property'  => 'account_creation_disabled_msg',
			'transform' => null,
		),
		'custom_restricted_domain_message'         => array(
			'class'     => 'Custom_Messages_Data',
			'property'  => 'restricted_domain_error_msg',
			'transform' => null,
		),
		'metadata_sync_url'                        => array(
			'class'     => 'Metadata_Sync_Data',
			'property'  => 'metadata_url',
			'transform' => null,
			'anomaly'   => 'enable_metadata_sync',
		),
		'metadata_sync_interval'                   => array(
			'class'     => 'Metadata_Sync_Data',
			'property'  => 'sync_time_interval',
			'transform' => null,
		),
		'metadata_sync_certificate'                => array(
			'class'     => 'Metadata_Sync_Data',
			'property'  => 'sync_only_certificate',
			'transform' => null,
		),
		'metadata_sync_cron_action'                => array(
			'class'     => '',
			'property'  => '',
			'transform' => null,
		),
		'show_sso_user'                            => array(
			'class'     => 'SSO_User_Data',
			'property'  => 'sso_show_user',
			'transform' => 'true_to_checked',
		),
		'sso_user'                                 => array(
			'class'     => '',
			'property'  => '',
			'transform' => null,
		),
		'check_sso_user'                           => array(
			'class'     => '',
			'property'  => '',
			'transform' => null,
		),
	);
}
