<?php
/**
 * Legacy Options Configuration - ENTERPRISE VERSION.
 *
 * @package    MOSAML
 * @subpackage MOSAML/src/handler/import-export/version-mappings
 */

namespace MOSAML\SRC\Handler\Import_Export\Version_Mappings;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Legacy Options Enum - Enterprise.
 */
class Legacy_Options_Enum_Enterprise {

	const CLASS_IMPORT_ORDER = array(
		'SP_Setup_Data',
		'Attribute_Mapping_Data',
		'Role_Mapping_Data',
		'Role_Assignment_Settings_Data',
		'Role_Mapping_Advanced_Settings_Data',
		'Relay_State_Data',
		'Metadata_Sync_Data',
		'SSO_Button_Data',
		'Shortcode_Widget_Data',
	);

	const CONFIG_KEY_TO_COMMON_MAP = array(
		'login_relay_state'                     => array(
			'class'       => 'Relay_State_Data',
			'property'    => 'login_relay_state',
			'transform'   => null,
			'specific_to' => 'idp',
		),
		'logout_relay_state'                    => array(
			'class'       => 'Relay_State_Data',
			'property'    => 'logout_relay_state',
			'transform'   => null,
			'specific_to' => 'idp',
		),
		'enable_auto_redirect'                  => array(
			'class'     => 'Site_Auto_Redirection_Data',
			'property'  => 'enable_site_auto_redirect',
			'transform' => 'true_to_checked',
		),
		'redirect_default_idp'                  => array(
			'class'     => 'Site_Auto_Redirection_Data',
			'property'  => 'site_auto_redirection_option',
			'transform' => 'true_to_default_idp',
		),
		'redirect_to_wp_login'                  => array(
			'class'     => 'Site_Auto_Redirection_Data',
			'property'  => 'site_auto_redirection_option',
			'transform' => 'true_to_wp_login',
		),
		'auto_redirect_to_public_page'          => array(
			'class'     => 'Site_Auto_Redirection_Data',
			'property'  => 'site_auto_redirection_option',
			'transform' => 'true_to_public_page',
		),
		'public_page_url'                       => array(
			'class'     => 'Site_Auto_Redirection_Data',
			'property'  => 'public_page_url',
			'transform' => null,
		),
		'force_authentication'                  => array(
			'class'     => 'Force_Authentication_Data',
			'property'  => 'enable_force_authentication',
			'transform' => null,
		),
		'enable_access_rss'                     => array(
			'class'     => 'RSS_Feed_Access_Data',
			'property'  => 'enable_rss_feed_access',
			'transform' => 'true_to_checked',
		),
		'shortcode_login_text'                  => array(
			'class'     => 'Shortcode_Data',
			'property'  => 'shortcode_login_text',
			'transform' => null,
		),
		'hide_wp_login'                         => array(
			'class'     => 'Hide_WP_Login_Data',
			'property'  => 'hide_wp_login',
			'transform' => 'true_to_checked',
		),
		'allow_wp_login'                        => array(
			'class'     => 'Backdoor_Url_Login_Data',
			'property'  => 'enable_backdoor_url_login',
			'transform' => 'true_to_checked',
		),
		'backdoor_url'                          => array(
			'class'     => 'Backdoor_Url_Login_Data',
			'property'  => 'backdoor_url',
			'transform' => null,
		),
		'redirect_to_default_idp_from_wp_login' => array(
			'class'     => 'Login_Page_Auto_Redirection_Data',
			'property'  => 'redirect_from_wp_login',
			'transform' => 'true_to_checked',
		),
		'sso_button'                            => array(
			'class'       => 'SSO_Button_Data',
			'property'    => '',
			'transform'   => null,
			'specific_to' => 'idp',
		),
		'add_button_wp_login'                   => array(
			'class'     => 'SSO_Button_Data',
			'property'  => 'enable_sso_button',
			'transform' => 'true_to_checked',
		),
		'use_button_as_shortcode'               => array(
			'class'     => 'SSO_Button_Data',
			'property'  => 'use_button_as_shortcode',
			'transform' => 'true_to_checked',
		),
		'use_button_as_widget'                  => array(
			'class'     => 'SSO_Button_Data',
			'property'  => 'use_button_as_widget',
			'transform' => 'true_to_checked',
		),
		'button_type'                           => array(
			'class'     => 'SSO_Button_Data',
			'property'  => 'sso_button_config',
			'transform' => 'button_attributes',
		),
		'button_size'                           => array(
			'class'     => 'SSO_Button_Data',
			'property'  => 'sso_button_config',
			'transform' => 'button_attributes',
		),
		'button_width'                          => array(
			'class'     => 'SSO_Button_Data',
			'property'  => 'sso_button_config',
			'transform' => 'button_attributes',
		),
		'button_height'                         => array(
			'class'     => 'SSO_Button_Data',
			'property'  => 'sso_button_config',
			'transform' => 'button_attributes',
		),
		'button_curve'                          => array(
			'class'     => 'SSO_Button_Data',
			'property'  => 'sso_button_config',
			'transform' => 'button_attributes',
		),
		'button_color'                          => array(
			'class'     => 'SSO_Button_Data',
			'property'  => 'sso_button_config',
			'transform' => 'button_attributes',
		),
		'button_text'                           => array(
			'class'     => 'SSO_Button_Data',
			'property'  => 'sso_button_config',
			'transform' => 'button_attributes',
		),
		'font_color'                            => array(
			'class'     => 'SSO_Button_Data',
			'property'  => 'sso_button_config',
			'transform' => 'button_font_attributes',
		),
		'font_size'                             => array(
			'class'     => 'SSO_Button_Data',
			'property'  => 'sso_button_config',
			'transform' => 'button_font_attributes',
		),
		'button_position'                       => array(
			'class'     => 'SSO_Button_Data',
			'property'  => 'sso_button_config',
			'transform' => 'button_attributes',
		),
		'saml_login_widget'                     => array(
			'class'     => '',
			'property'  => '',
			'transform' => null,
			'anomaly'   => 'save_wp_widget_config',
		),
		'keep_configuration_intact'             => array(
			'class'     => '',
			'property'  => '',
			'transform' => null,
		),
		'sp_base_url'                           => array(
			'class'     => 'SP_Endpoints_Data',
			'property'  => 'sp_base_url',
			'transform' => 'empty_to_default',
		),
		'sp_entity_id'                          => array(
			'class'     => 'SP_Endpoints_Data',
			'property'  => 'sp_entity_id',
			'transform' => 'empty_to_default',
		),
		'identity_name'                         => array(
			'class'       => '',
			'property'    => '',
			'transform'   => null,
			'specific_to' => 'idp',
		),
		'idp_name'                              => array(
			'class'     => 'SP_Setup_Data',
			'property'  => 'idp_id',
			'transform' => null,
		),
		'idp_display_name'                      => array(
			'class'     => 'SP_Setup_Data',
			'property'  => 'idp_name',
			'transform' => null,
		),
		'idp_entity_id'                         => array(
			'class'     => 'SP_Setup_Data',
			'property'  => 'entity_id',
			'transform' => null,
		),
		'saml_sp_entity_id'                     => array(
			'class'     => 'SP_Setup_Data',
			'property'  => 'sp_entity_id',
			'transform' => null,
		),
		'sso_url'                               => array(
			'class'     => 'SP_Setup_Data',
			'property'  => 'sso_url',
			'transform' => null,
		),
		'sso_binding_type'                      => array(
			'class'     => 'SP_Setup_Data',
			'property'  => 'sso_binding',
			'transform' => null,
		),
		'slo_url'                               => array(
			'class'     => 'SP_Setup_Data',
			'property'  => 'slo_url',
			'transform' => null,
		),
		'slo_binding_type'                      => array(
			'class'     => 'SP_Setup_Data',
			'property'  => 'slo_binding',
			'transform' => null,
		),
		'x509_certificate'                      => array(
			'class'     => 'SP_Setup_Data',
			'property'  => 'idp_certificate',
			'transform' => null,
		),
		'response_signed'                       => array(
			'class'     => '',
			'property'  => '',
			'transform' => null,
		),
		'assertion_signed'                      => array(
			'class'     => '',
			'property'  => '',
			'transform' => null,
		),
		'request_signed'                        => array(
			'class'     => 'SP_Setup_Data',
			'property'  => 'sign_sso_slo_request',
			'transform' => null,
		),
		'nameid_format'                         => array(
			'class'     => 'SP_Setup_Data',
			'property'  => 'name_id_format',
			'transform' => 'prepare_name_id_format',
		),
		'mo_saml_encoding_enabled'              => array(
			'class'     => 'SP_Setup_Data',
			'property'  => 'character_encoding',
			'transform' => 'true_to_checked',
		),
		'mo_saml_assertion_time_validity'       => array(
			'class'     => 'SP_Setup_Data',
			'property'  => 'assertion_time_validity',
			'transform' => null,
		),
		'saml_pw_reset_url'                     => array(
			'class'     => 'SP_Setup_Data',
			'property'  => 'password_reset_url',
			'transform' => null,
		),
		'enable_idp'                            => array(
			'class'     => 'SP_Setup_Data',
			'property'  => 'status',
			'transform' => 'true_to_active',
		),
		'custom_login_text'                     => array(
			'class'     => 'Shortcode_Widget_Data',
			'property'  => 'widget_config',
			'transform' => 'add_to_widget_config',
		),
		'custom_greeting_text'                  => array(
			'class'     => 'Shortcode_Widget_Data',
			'property'  => 'widget_config',
			'transform' => 'add_to_widget_config',
		),
		'greeting_name'                         => array(
			'class'     => 'Shortcode_Widget_Data',
			'property'  => 'widget_config',
			'transform' => 'add_to_widget_config',
		),
		'custom_logout_text'                    => array(
			'class'     => 'Shortcode_Widget_Data',
			'property'  => 'widget_config',
			'transform' => 'add_to_widget_config',
		),
		'saml_request'                          => array(
			'class'     => 'SP_Setup_Data',
			'property'  => 'saml_request',
			'transform' => null,
		),
		'saml_response'                         => array(
			'class'     => 'SP_Setup_Data',
			'property'  => 'saml_response',
			'transform' => null,
		),
		'test_status'                           => array(
			'class'     => '',
			'property'  => '',
			'transform' => null,
		),
		'enable_domain_mapping'                 => array(
			'class'     => 'Domain_Mapping_Data',
			'property'  => 'enable_domain_mapping',
			'transform' => 'true_to_checked',
		),
		'domain_login_failed_option'            => array(
			'class'     => '',
			'property'  => '',
			'transform' => null,
		),
		'domain_mapping_idp'                    => array(
			'class'     => 'Domain_Mapping_Data',
			'property'  => 'domain_mapping_config',
			'transform' => null,
		),
		'domain_login_fail'                     => array(
			'class'     => '',
			'property'  => '',
			'transform' => null,
		),
		'fallback_to_default'                   => array(
			'class'     => 'Domain_Mapping_Data',
			'property'  => 'domain_mapping_fail_option',
			'transform' => 'true_to_default_idp',
		),
		'attribute_custom_mapping'              => array(
			'class'       => 'Attribute_Mapping_Data',
			'property'    => 'custom_attributes',
			'transform'   => 'format_custom_attributes',
			'specific_to' => 'idp',
		),
		'attribute_show_in_user_menu'           => array(
			'class'       => 'Attribute_Mapping_Data',
			'property'    => 'custom_attributes',
			'transform'   => 'format_custom_attributes_display',
			'specific_to' => 'idp',
		),
		'attribute_mapping'                     => array(
			'class'       => '',
			'property'    => '',
			'transform'   => null,
			'specific_to' => 'idp',
		),
		'username'                              => array(
			'class'     => 'Attribute_Mapping_Data',
			'property'  => 'user_name',
			'transform' => null,
		),
		'email'                                 => array(
			'class'     => 'Attribute_Mapping_Data',
			'property'  => 'email',
			'transform' => null,
		),
		'first_name'                            => array(
			'class'     => 'Attribute_Mapping_Data',
			'property'  => 'first_name',
			'transform' => null,
		),
		'last_name'                             => array(
			'class'     => 'Attribute_Mapping_Data',
			'property'  => 'last_name',
			'transform' => null,
		),
		'nick_name'                             => array(
			'class'     => 'Attribute_Mapping_Data',
			'property'  => 'nick_name',
			'transform' => null,
		),
		'display_name'                          => array(
			'class'     => 'Attribute_Mapping_Data',
			'property'  => 'display_name',
			'transform' => null,
		),
		'do_not_update_display_name'            => array(
			'class'     => 'Attribute_Mapping_Data',
			'property'  => 'do_not_update_display_name',
			'transform' => 'true_to_checked',
		),
		'role_mapping_idp'                      => array(
			'class'       => '',
			'property'    => '',
			'transform'   => null,
			'specific_to' => 'idp',
		),
		'role_mapping_configurations'           => array(
			'class'       => '',
			'property'    => '',
			'transform'   => null,
			'specific_to' => 'idp',
		),
		'group_name'                            => array(
			'class'     => 'Role_Assignment_Settings_Data',
			'property'  => 'group_attribute_name',
			'transform' => null,
		),
		'apply_role_to_admin'                   => array(
			'class'     => 'Role_Assignment_Settings_Data',
			'property'  => 'apply_role_mapping_to_admin',
			'transform' => null,
		),
		'create_new_user'                       => array(
			'class'     => 'Role_Assignment_Settings_Data',
			'property'  => 'create_new_user',
			'transform' => 'true_to_checked',
		),
		'default_role_for_new_users'            => array(
			'class'     => 'Role_Assignment_Settings_Data',
			'property'  => 'default_role_new',
			'transform' => 'validate_wp_role',
		),
		'update_existing_user'                  => array(
			'class'     => 'Role_Assignment_Settings_Data',
			'property'  => 'update_existing_user',
			'transform' => 'true_to_checked',
		),
		'default_role_for_existing_users'       => array(
			'class'     => 'Role_Assignment_Settings_Data',
			'property'  => 'default_role_existing',
			'transform' => 'validate_wp_role',
		),
		'configured_role_values'                => array(
			'class'       => 'Role_Mapping_Data',
			'property'    => 'role_mapping_values',
			'transform'   => null,
			'specific_to' => 'idp',
		),
		'custom_public_certificate'             => array(
			'class'     => 'Certificate_Data',
			'property'  => 'public_key',
			'transform' => null,
		),
		'custom_private_certificate'            => array(
			'class'     => 'Certificate_Data',
			'property'  => 'private_key',
			'transform' => null,
		),
		'domain_restriction_idp'                => array(
			'class'     => '',
			'property'  => '',
			'transform' => null,
		),
		'account_creation_disabled_msg'         => array(
			'class'     => 'Custom_Messages_Data',
			'property'  => 'account_creation_disabled_msg',
			'transform' => null,
		),
		'restricted_domain_msg'                 => array(
			'class'     => 'Custom_Messages_Data',
			'property'  => 'restricted_domain_error_msg',
			'transform' => null,
		),
		'test_config_attibutes'                 => array(
			'class'       => 'SP_Setup_Data',
			'property'    => 'test_config_attributes',
			'transform'   => null,
			'specific_to' => 'idp',
		),
		'sync_url'                              => array(
			'class'       => '',
			'property'    => '',
			'transform'   => null,
			'anomaly'     => '',
			'specific_to' => 'idp',
		),
		'metadata_url'                          => array(
			'class'     => 'Metadata_Sync_Data',
			'property'  => 'metadata_url',
			'transform' => null,
			'anomaly'   => 'enable_metadata_sync',
		),
		'sync_interval'                         => array(
			'class'     => 'Metadata_Sync_Data',
			'property'  => 'sync_time_interval',
			'transform' => null,
		),
		'sync_certificate_metadata'             => array(
			'class'     => 'Metadata_Sync_Data',
			'property'  => 'sync_only_certificate',
			'transform' => null,
		),
		'advanced_settings'                     => array(
			'class'       => '',
			'property'    => '',
			'transform'   => null,
			'specific_to' => 'idp',
		),
		'allow_deny_user_attribute'             => array(
			'class'     => 'Role_Mapping_Advanced_Settings_Data',
			'property'  => 'allow_deny_idp_attribute_toggle',
			'transform' => null,
		),
		'keep_existing_users_role'              => array(
			'class'     => 'Role_Mapping_Advanced_Settings_Data',
			'property'  => 'do_not_update_existing_user_roles',
			'transform' => null,
		),
		'restricted_attribute'                  => array(
			'class'     => 'Role_Mapping_Advanced_Settings_Data',
			'property'  => 'attribute_restriction_group',
			'transform' => null,
		),
		'restricted_attribute_values'           => array(
			'class'     => 'Role_Mapping_Advanced_Settings_Data',
			'property'  => 'attribute_restriction_value',
			'transform' => null,
		),
		'allow_deny_attr_option'                => array(
			'class'     => 'Role_Mapping_Advanced_Settings_Data',
			'property'  => 'allow_deny_idp_attribute',
			'transform' => null,
		),
		'allow_deny_user_domain'                => array(
			'class'     => 'Role_Mapping_Advanced_Settings_Data',
			'property'  => 'allow_deny_user_domain_toggle',
			'transform' => null,
		),
		'restricted_domains'                    => array(
			'class'     => 'Role_Mapping_Advanced_Settings_Data',
			'property'  => 'allow_deny_user_domain_value',
			'transform' => null,
		),
		'allow_deny_domain_option'              => array(
			'class'     => 'Role_Mapping_Advanced_Settings_Data',
			'property'  => 'allow_deny_user_domain_type',
			'transform' => null,
		),
		'enable_regex'                          => array(
			'class'     => 'Role_Mapping_Advanced_Settings_Data',
			'property'  => 'enable_regex_for_role_mapping',
			'transform' => null,
		),
		'do_not_create_new_users'               => array(
			'class'     => 'Role_Mapping_Advanced_Settings_Data',
			'property'  => 'do_not_create_new_users',
			'transform' => null,
		),
		'whitelisted_roles'                     => array(
			'class'     => 'Role_Mapping_Advanced_Settings_Data',
			'property'  => 'whitelisted_roles',
			'transform' => null,
		),
		'whitelist_existing_users_roles'        => array(
			'class'     => 'Role_Mapping_Advanced_Settings_Data',
			'property'  => 'whitelist_existing_users_roles',
			'transform' => null,
		),
		'organization_name_option'              => array(
			'class'     => 'SP_Organization_Data',
			'property'  => 'organization_name',
			'transform' => null,
		),
		'organization_display_name_option'      => array(
			'class'     => 'SP_Organization_Data',
			'property'  => 'organization_display_name',
			'transform' => null,
		),
		'organization_url_option'               => array(
			'class'     => 'SP_Organization_Data',
			'property'  => 'organization_url',
			'transform' => null,
		),
		'technical_person_name_option'          => array(
			'class'     => 'SP_Organization_Data',
			'property'  => 'technical_person_name',
			'transform' => null,
		),
		'technical_person_email_option'         => array(
			'class'     => 'SP_Organization_Data',
			'property'  => 'technical_person_email',
			'transform' => null,
		),
		'support_person_name_option'            => array(
			'class'     => 'SP_Organization_Data',
			'property'  => 'support_person_name',
			'transform' => null,
		),
		'support_person_email_option'           => array(
			'class'     => 'SP_Organization_Data',
			'property'  => 'support_person_email',
			'transform' => null,
		),
		'show_sso_user'                         => array(
			'class'     => 'SSO_User_Data',
			'property'  => 'sso_show_user',
			'transform' => 'true_to_checked',
		),
		'sso_user'                              => array(
			'class'     => '',
			'property'  => '',
			'transform' => null,
		),
		'check_sso_user'                        => array(
			'class'     => '',
			'property'  => '',
			'transform' => null,
		),
	);

	const MULTIPLE_ENV_CONFIG_KEY_TO_COMMON_MAP = array(
		'wp_site_url'                           => array(
			'class'     => 'Multiple_Environments_Data',
			'property'  => 'environment_url',
			'transform' => null,
		),
		'saml_identity_providers'               => array(
			'class'       => '',
			'property'    => '',
			'transform'   => null,
			'specific_to' => 'idp',
		),
		'idp_name'                              => array(
			'class'     => 'SP_Setup_Data',
			'property'  => 'idp_id',
			'transform' => null,
		),
		'idp_display_name'                      => array(
			'class'     => 'SP_Setup_Data',
			'property'  => 'idp_name',
			'transform' => null,
		),
		'idp_entity_id'                         => array(
			'class'     => 'SP_Setup_Data',
			'property'  => 'entity_id',
			'transform' => null,
		),
		'saml_sp_entity_id'                     => array(
			'class'     => 'SP_Setup_Data',
			'property'  => 'sp_entity_id',
			'transform' => null,
		),
		'sso_url'                               => array(
			'class'     => 'SP_Setup_Data',
			'property'  => 'sso_url',
			'transform' => null,
		),
		'sso_binding_type'                      => array(
			'class'     => 'SP_Setup_Data',
			'property'  => 'sso_binding',
			'transform' => null,
		),
		'slo_url'                               => array(
			'class'     => 'SP_Setup_Data',
			'property'  => 'slo_url',
			'transform' => null,
		),
		'slo_binding_type'                      => array(
			'class'     => 'SP_Setup_Data',
			'property'  => 'slo_binding',
			'transform' => null,
		),
		'x509_certificate'                      => array(
			'class'     => 'SP_Setup_Data',
			'property'  => 'idp_certificate',
			'transform' => null,
		),
		'response_signed'                       => array(
			'class'     => '',
			'property'  => '',
			'transform' => null,
		),
		'assertion_signed'                      => array(
			'class'     => '',
			'property'  => '',
			'transform' => null,
		),
		'request_signed'                        => array(
			'class'     => 'SP_Setup_Data',
			'property'  => 'sign_sso_slo_request',
			'transform' => null,
		),
		'nameid_format'                         => array(
			'class'     => 'SP_Setup_Data',
			'property'  => 'name_id_format',
			'transform' => 'prepare_name_id_format',
		),
		'mo_saml_encoding_enabled'              => array(
			'class'     => 'SP_Setup_Data',
			'property'  => 'character_encoding',
			'transform' => 'true_to_checked',
		),
		'mo_saml_assertion_time_validity'       => array(
			'class'     => 'SP_Setup_Data',
			'property'  => 'assertion_time_validity',
			'transform' => null,
		),
		'saml_pw_reset_url'                     => array(
			'class'     => 'SP_Setup_Data',
			'property'  => 'password_reset_url',
			'transform' => null,
		),
		'enable_idp'                            => array(
			'class'     => 'SP_Setup_Data',
			'property'  => 'status',
			'transform' => 'true_to_active',
		),
		'custom_login_text'                     => array(
			'class'     => 'Shortcode_Widget_Data',
			'property'  => 'widget_config',
			'transform' => 'add_to_widget_config',
		),
		'custom_greeting_text'                  => array(
			'class'     => 'Shortcode_Widget_Data',
			'property'  => 'widget_config',
			'transform' => 'add_to_widget_config',
		),
		'greeting_name'                         => array(
			'class'     => 'Shortcode_Widget_Data',
			'property'  => 'widget_config',
			'transform' => 'add_to_widget_config',
		),
		'custom_logout_text'                    => array(
			'class'     => 'Shortcode_Widget_Data',
			'property'  => 'widget_config',
			'transform' => 'add_to_widget_config',
		),
		'saml_request'                          => array(
			'class'     => 'SP_Setup_Data',
			'property'  => 'saml_request',
			'transform' => null,
		),
		'saml_response'                         => array(
			'class'     => 'SP_Setup_Data',
			'property'  => 'saml_response',
			'transform' => null,
		),
		'test_status'                           => array(
			'class'     => '',
			'property'  => '',
			'transform' => null,
		),
		'mo_saml_idp_name_id_map'               => array(
			'class'     => '',
			'property'  => '',
			'transform' => null,
		),
		'saml_metadata_url_for_sync'            => array(
			'class'       => '',
			'property'    => '',
			'transform'   => null,
			'specific_to' => 'idp',
		),
		'metadata_url'                          => array(
			'class'     => 'Metadata_Sync_Data',
			'property'  => 'metadata_url',
			'transform' => null,
			'anomaly'   => 'enable_metadata_sync',
		),
		'sync_interval'                         => array(
			'class'     => 'Metadata_Sync_Data',
			'property'  => 'sync_time_interval',
			'transform' => null,
		),
		'sync_certificate_metadata'             => array(
			'class'     => 'Metadata_Sync_Data',
			'property'  => 'sync_only_certificate',
			'transform' => null,
		),
		'saml_sync_ceritificate_metadata'       => array(
			'class'     => '',
			'property'  => '',
			'transform' => null,
		),
		'mo_saml_sp_base_url'                   => array(
			'class'     => 'SP_Endpoints_Data',
			'property'  => 'sp_base_url',
			'transform' => null,
		),
		'mo_saml_sp_entity_id'                  => array(
			'class'     => 'SP_Endpoints_Data',
			'property'  => 'sp_entity_id',
			'transform' => null,
		),
		'mo_saml_metadata_org_name'             => array(
			'class'     => '',
			'property'  => '',
			'transform' => null,
		),
		'mo_saml_metadata_org_email'            => array(
			'class'     => '',
			'property'  => '',
			'transform' => null,
		),
		'mo_saml_metadata_org_url'              => array(
			'class'     => '',
			'property'  => '',
			'transform' => null,
		),
		'mo_saml_relay_state'                   => array(
			'class'     => '',
			'property'  => '',
			'transform' => null,
		),
		'login_relay_state'                     => array(
			'class'       => 'Relay_State_Data',
			'property'    => 'login_relay_state',
			'transform'   => null,
			'specific_to' => 'idp',
		),
		'logout_relay_state'                    => array(
			'class'       => 'Relay_State_Data',
			'property'    => 'logout_relay_state',
			'transform'   => null,
			'specific_to' => 'idp',
		),
		'mo_saml_enable_auto_redirect'          => array(
			'class'     => 'Site_Auto_Redirection_Data',
			'property'  => 'enable_site_auto_redirect',
			'transform' => null,
		),
		'mo_saml_redirect_default_idp'          => array(
			'class'     => 'Site_Auto_Redirection_Data',
			'property'  => 'site_auto_redirection_option',
			'transform' => 'true_to_default_idp',
		),
		'mo_saml_registered_only_access'        => array(
			'class'     => 'Site_Auto_Redirection_Data',
			'property'  => 'site_auto_redirection_option',
			'transform' => 'true_to_wp_login',
		),
		'mo_saml_auto_redirect_to_public_page'  => array(
			'class'     => 'Site_Auto_Redirection_Data',
			'property'  => 'site_auto_redirection_option',
			'transform' => 'true_to_public_page',
		),
		'mo_saml_idp_list_url'                  => array(
			'class'     => 'Site_Auto_Redirection_Data',
			'property'  => 'public_page_url',
			'transform' => null,
		),
		'mo_saml_force_authentication'          => array(
			'class'     => 'Force_Authentication_Data',
			'property'  => 'enable_force_authentication',
			'transform' => null,
		),
		'mo_saml_enable_rss_access'             => array(
			'class'     => 'RSS_Feed_Access_Data',
			'property'  => 'enable_rss_feed_access',
			'transform' => null,
		),
		'mo_saml_shortcode_login_text'          => array(
			'class'     => 'Shortcode_Data',
			'property'  => 'shortcode_login_text',
			'transform' => null,
		),
		'mo_saml_allow_wp_signin'               => array(
			'class'     => 'Backdoor_Url_Login_Data',
			'property'  => 'enable_backdoor_url_login',
			'transform' => 'true_to_checked',
		),
		'mo_saml_backdoor_url'                  => array(
			'class'     => 'Backdoor_Url_Login_Data',
			'property'  => 'backdoor_url',
			'transform' => null,
		),
		'mo_saml_enable_hide_wp_login'          => array(
			'class'     => 'Hide_WP_Login_Data',
			'property'  => 'hide_wp_login',
			'transform' => 'true_to_checked',
		),
		'saml_sso_button_idp'                   => array(
			'class'       => '',
			'property'    => '',
			'transform'   => null,
			'specific_to' => 'idp',
		),
		'add_button_wp_login'                   => array(
			'class'     => 'SSO_Button_Data',
			'property'  => 'enable_sso_button',
			'transform' => 'true_to_checked',
		),
		'use_button_as_shortcode'               => array(
			'class'     => 'SSO_Button_Data',
			'property'  => 'use_button_as_shortcode',
			'transform' => 'true_to_checked',
		),
		'use_button_as_widget'                  => array(
			'class'     => 'SSO_Button_Data',
			'property'  => 'use_button_as_widget',
			'transform' => 'true_to_checked',
		),
		'button_type'                           => array(
			'class'     => 'SSO_Button_Data',
			'property'  => 'sso_button_config',
			'transform' => 'button_attributes',
		),
		'button_size'                           => array(
			'class'     => 'SSO_Button_Data',
			'property'  => 'sso_button_config',
			'transform' => 'button_attributes',
		),
		'button_width'                          => array(
			'class'     => 'SSO_Button_Data',
			'property'  => 'sso_button_config',
			'transform' => 'button_attributes',
		),
		'button_height'                         => array(
			'class'     => 'SSO_Button_Data',
			'property'  => 'sso_button_config',
			'transform' => 'button_attributes',
		),
		'button_curve'                          => array(
			'class'     => 'SSO_Button_Data',
			'property'  => 'sso_button_config',
			'transform' => 'button_attributes',
		),
		'button_color'                          => array(
			'class'     => 'SSO_Button_Data',
			'property'  => 'sso_button_config',
			'transform' => 'button_attributes',
		),
		'button_text'                           => array(
			'class'     => 'SSO_Button_Data',
			'property'  => 'sso_button_config',
			'transform' => 'button_attributes',
		),
		'font_color'                            => array(
			'class'     => 'SSO_Button_Data',
			'property'  => 'sso_button_config',
			'transform' => 'button_font_attributes',
		),
		'font_size'                             => array(
			'class'     => 'SSO_Button_Data',
			'property'  => 'sso_button_config',
			'transform' => 'button_font_attributes',
		),
		'button_position'                       => array(
			'class'     => 'SSO_Button_Data',
			'property'  => 'sso_button_config',
			'transform' => 'button_attributes',
		),
		'saml_login_widget'                     => array(
			'class'     => '',
			'property'  => '',
			'transform' => null,
		),
		'mo_saml_enable_login_redirect'         => array(
			'class'     => 'Login_Page_Auto_Redirection_Data',
			'property'  => 'redirect_from_wp_login',
			'transform' => 'true_to_checked',
		),
		'mo_saml_account_creation_disabled_msg' => array(
			'class'     => 'Custom_Messages_Data',
			'property'  => 'account_creation_disabled_msg',
			'transform' => null,
		),
		'mo_saml_restricted_domain_error_msg'   => array(
			'class'     => 'Custom_Messages_Data',
			'property'  => 'restricted_domain_error_msg',
			'transform' => null,
		),
		'mo_saml_enable_domain_mapping'         => array(
			'class'     => 'Domain_Mapping_Data',
			'property'  => 'enable_domain_mapping',
			'transform' => 'true_to_checked',
		),
		'domain_login_failed_option'            => array(
			'class'     => '',
			'property'  => '',
			'transform' => null,
		),
		'saml_idp_domain_mapping'               => array(
			'class'     => 'Domain_Mapping_Data',
			'property'  => 'domain_mapping_config',
			'transform' => null,
		),
		'mo_saml_domain_login_fail'             => array(
			'class'     => '',
			'property'  => '',
			'transform' => null,
		),
		'mo_saml_fallback_to_default'           => array(
			'class'     => 'Domain_Mapping_Data',
			'property'  => 'domain_mapping_fail_option',
			'transform' => 'true_to_default_idp',
		),
		'mo_saml_custom_attrs_mapping'          => array(
			'class'       => 'Attribute_Mapping_Data',
			'property'    => 'custom_attributes',
			'transform'   => 'format_custom_attributes',
			'specific_to' => 'idp',
		),
		'saml_attrs_to_display_idp'             => array(
			'class'       => 'Attribute_Mapping_Data',
			'property'    => 'custom_attributes',
			'transform'   => 'format_custom_attributes_display',
			'specific_to' => 'idp',
		),
		'saml_idp_attribute_mapping'            => array(
			'class'     => '',
			'property'  => '',
			'transform' => null,
		),
		'mo_saml_attribute_mapping'             => array(
			'class'       => '',
			'property'    => '',
			'transform'   => null,
			'specific_to' => 'idp',
		),
		'username'                              => array(
			'class'     => 'Attribute_Mapping_Data',
			'property'  => 'user_name',
			'transform' => null,
		),
		'email'                                 => array(
			'class'     => 'Attribute_Mapping_Data',
			'property'  => 'email',
			'transform' => null,
		),
		'first_name'                            => array(
			'class'     => 'Attribute_Mapping_Data',
			'property'  => 'first_name',
			'transform' => null,
		),
		'last_name'                             => array(
			'class'     => 'Attribute_Mapping_Data',
			'property'  => 'last_name',
			'transform' => null,
		),
		'display_name'                          => array(
			'class'     => 'Attribute_Mapping_Data',
			'property'  => 'display_name',
			'transform' => null,
		),
		'nick_name'                             => array(
			'class'     => 'Attribute_Mapping_Data',
			'property'  => 'nick_name',
			'transform' => null,
		),
		'do_not_update_display_name'            => array(
			'class'     => 'Attribute_Mapping_Data',
			'property'  => 'do_not_update_display_name',
			'transform' => null,
		),
		'saml_domain_restriction'               => array(
			'class'     => '',
			'property'  => '',
			'transform' => null,
		),
		'saml_domain_restriction_idp'           => array(
			'class'       => '',
			'property'    => '',
			'transform'   => null,
			'specific_to' => 'idp',
		),
		'saml_idp_role_mapping'                 => array(
			'class'       => '',
			'property'    => '',
			'transform'   => null,
			'specific_to' => 'idp',
		),
		'role_mapping_idp_name'                 => array(
			'class'     => '',
			'property'  => '',
			'transform' => null,
		),
		'mo_saml_role_mapping_configurations'   => array(
			'class'       => '',
			'property'    => '',
			'transform'   => null,
			'specific_to' => 'idp',
		),
		'group_name'                            => array(
			'class'     => 'Role_Assignment_Settings_Data',
			'property'  => 'group_attribute_name',
			'transform' => null,
		),
		'apply_role_to_admin'                   => array(
			'class'     => 'Role_Assignment_Settings_Data',
			'property'  => 'apply_role_mapping_to_admin',
			'transform' => null,
		),
		'create_new_user'                       => array(
			'class'     => 'Role_Assignment_Settings_Data',
			'property'  => 'create_new_user',
			'transform' => 'true_to_checked',
		),
		'default_role_for_new_users'            => array(
			'class'     => 'Role_Assignment_Settings_Data',
			'property'  => 'default_role_new',
			'transform' => 'validate_wp_role',
		),
		'update_existing_user'                  => array(
			'class'     => 'Role_Assignment_Settings_Data',
			'property'  => 'update_existing_user',
			'transform' => 'true_to_checked',
		),
		'default_role_for_existing_users'       => array(
			'class'     => 'Role_Assignment_Settings_Data',
			'property'  => 'default_role_existing',
			'transform' => 'validate_wp_role',
		),
		'mo_saml_configured_role_values'        => array(
			'class'       => 'Role_Mapping_Data',
			'property'    => 'role_mapping_values',
			'transform'   => null,
			'specific_to' => 'idp',
		),
		'mo_saml_attr_role_advanced_settings'   => array(
			'class'       => '',
			'property'    => '',
			'transform'   => null,
			'specific_to' => 'idp',
		),
		'allow_deny_user_attribute'             => array(
			'class'     => 'Role_Mapping_Advanced_Settings_Data',
			'property'  => 'allow_deny_idp_attribute_toggle',
			'transform' => null,
		),
		'keep_existing_users_role'              => array(
			'class'     => 'Role_Mapping_Advanced_Settings_Data',
			'property'  => 'do_not_update_existing_user_roles',
			'transform' => null,
		),
		'restricted_attribute'                  => array(
			'class'     => 'Role_Mapping_Advanced_Settings_Data',
			'property'  => 'attribute_restriction_group',
			'transform' => null,
		),
		'restricted_attribute_values'           => array(
			'class'     => 'Role_Mapping_Advanced_Settings_Data',
			'property'  => 'attribute_restriction_value',
			'transform' => null,
		),
		'allow_deny_attr_option'                => array(
			'class'     => 'Role_Mapping_Advanced_Settings_Data',
			'property'  => 'allow_deny_idp_attribute',
			'transform' => null,
		),
		'allow_deny_user_domain'                => array(
			'class'     => 'Role_Mapping_Advanced_Settings_Data',
			'property'  => 'allow_deny_user_domain_toggle',
			'transform' => null,
		),
		'restricted_domains'                    => array(
			'class'     => 'Role_Mapping_Advanced_Settings_Data',
			'property'  => 'allow_deny_user_domain_value',
			'transform' => null,
		),
		'allow_deny_domain_option'              => array(
			'class'     => 'Role_Mapping_Advanced_Settings_Data',
			'property'  => 'allow_deny_user_domain_type',
			'transform' => null,
		),
		'enable_regex'                          => array(
			'class'     => 'Role_Mapping_Advanced_Settings_Data',
			'property'  => 'enable_regex_for_role_mapping',
			'transform' => null,
		),
		'do_not_create_new_users'               => array(
			'class'     => 'Role_Mapping_Advanced_Settings_Data',
			'property'  => 'do_not_create_new_users',
			'transform' => null,
		),
		'whitelisted_roles'                     => array(
			'class'     => 'Role_Mapping_Advanced_Settings_Data',
			'property'  => 'whitelisted_roles',
			'transform' => null,
		),
		'whitelist_existing_users_roles'        => array(
			'class'     => 'Role_Mapping_Advanced_Settings_Data',
			'property'  => 'whitelist_existing_users_roles',
			'transform' => null,
		),
		'mo_saml_test_config_attrs'             => array(
			'class'       => 'SP_Setup_Data',
			'property'    => 'test_config_attributes',
			'transform'   => null,
			'specific_to' => 'idp',
		),
		'mo_saml_sso_show_user'                 => array(
			'class'     => 'SSO_User_Data',
			'property'  => 'sso_show_user',
			'transform' => 'true_to_checked',
		),
	);
}
