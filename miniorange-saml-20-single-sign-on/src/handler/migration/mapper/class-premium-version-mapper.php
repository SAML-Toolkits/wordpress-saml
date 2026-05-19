<?php
/**
 * Premium Version Mapper.
 *
 * @package    MOSAML
 * @subpackage MOSAML/src/handler/migration/mapper
 */

namespace MOSAML\SRC\Handler\Migration\Mapper;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\SRC\Handler\Migration\Mapper\Legacy_Version_Mapper;
use MOSAML\SRC\Handler\Migration\Model\Normalized_Migration_Model;
use MOSAML\SRC\Handler\Migration\Helper\Migration_Helper;
use MOSAML\SRC\Utils\Utility;
use MOSAML\SRC\Constant\Constants;

/**
 * Premium Version Mapper.
 */
class Premium_Version_Mapper implements Legacy_Version_Mapper {

	/**
	 * Map the enterprise version.
	 *
	 * @param array $methods The methods to map.
	 * @return object Normalized Migration Model.
	 * @throws \InvalidArgumentException If the method does not exist.
	 */
	public function map( $methods = array() ) {
		$normalized_model = new Normalized_Migration_Model();
		if ( empty( $methods ) || ! is_array( $methods ) ) {
			$methods = array(
				'map_environments',
				'map_global_options',
				'map_idp_details',
				'map_sp_metadata',
				'map_subsites',
				'map_attribute_mapping',
				'map_role_mapping',
				'map_sso_settings',
			);
		}

		foreach ( $methods as $method ) {
			if ( ! method_exists( $this, $method ) ) {
				throw new \InvalidArgumentException(
					sprintf( 'Invalid mapper method: %s', esc_html( $method ) )
				);
			}

			$this->{$method}( $normalized_model );
		}
		return $normalized_model;
	}

	/**
	 * Map the environments.
	 *
	 * @param Normalized_Migration_Model $normalized_model The normalized model.
	 * @return void
	 */
	private function map_environments( $normalized_model ) {
		$environment_name = str_replace( ' ', '_', get_bloginfo( 'name' ) );
		$environment_url  = Utility::parse_environment_url( site_url() );

		$normalized_model->environments[ $environment_url ] = array(
			'environment_name' => $environment_name,
			'environment_url'  => $environment_url,
			'is_selected'      => true,
		);
	}

	/**
	 * Map the global options.
	 *
	 * @param Normalized_Migration_Model $normalized_model The normalized model.
	 * @return void
	 */
	private function map_global_options( $normalized_model ) {
		$normalized_model->global_options['mosaml_enable_multiple_environments'] = get_option( 'mo_enable_multiple_licenses' );
		$normalized_model->global_options['mosaml_keep_settings_on_deletion']    = Migration_Helper::map_value( 'true_to_checked', get_option( 'mo_saml_keep_settings_on_deletion' ) );
	}

	/**
	 * Map the IDP details.
	 *
	 * @param Normalized_Migration_Model $normalized_model The normalized model.
	 * @return void
	 */
	private function map_idp_details( $normalized_model ) {
		$idp_name  = get_option( 'saml_identity_name' );
		$login_url = get_option( 'saml_login_url' );
		if ( empty( $idp_name ) && empty( $login_url ) ) {
			return;
		}

		$idp_id          = Utility::generate_idp_id();
		$environment_url = Utility::parse_environment_url( site_url() );
		$normalized_model->idp_details[ $environment_url ][ $idp_id ] = array(
			'idp_id'                  => $idp_id,
			'idp_name'                => $idp_name,
			'entity_id'               => get_option( 'saml_issuer' ),
			'sso_url'                 => $login_url,
			'slo_url'                 => get_option( 'saml_logout_url' ),
			'idp_certificate'         => maybe_unserialize( get_option( 'saml_x509_certificate' ) ),
			'character_encoding'      => get_option( 'mo_saml_encoding_enabled', 'checked' ),
			'assertion_time_validity' => get_option( 'mo_saml_assertion_time_validity', 'checked' ),
			'sign_sso_slo_request'    => get_option( 'saml_request_signed' ),
			'sso_binding'             => get_option( 'saml_login_binding_type', 'HttpRedirect' ),
			'slo_binding'             => get_option( 'saml_logout_binding_type', 'HttpRedirect' ),
			'sp_entity_id'            => get_option( 'mo_saml_sp_entity_id', home_url() . Constants::SP_ENTITY_ID ),
			'name_id_format'          => 'urn:oasis:names:tc:SAML:' . get_option( 'saml_nameid_format', '1.1:nameid-format:unspecified' ),
			'status'                  => 'active',
			'default_idp'             => true,
		);

		if ( ! isset( $normalized_model->idp_details[ $environment_url ][ $idp_id ] ) || empty( $normalized_model->idp_details[ $environment_url ][ $idp_id ] ) ) {
			return;
		}
		$sync_metadata_url = get_option( 'saml_metadata_url_for_sync' );
		if ( ! empty( $sync_metadata_url ) ) {
			$normalized_model->idp_details[ $environment_url ][ $idp_id ]['sync_metadata']         = 'checked';
			$normalized_model->idp_details[ $environment_url ][ $idp_id ]['metadata_url']          = $sync_metadata_url;
			$normalized_model->idp_details[ $environment_url ][ $idp_id ]['sync_time_interval']    = get_option( 'saml_metadata_sync_interval' );
			$normalized_model->idp_details[ $environment_url ][ $idp_id ]['sync_only_certificate'] = get_option( 'saml_sync_certificate_metadata' ) ? 'checked' : '';
		}

		$normalized_model->idp_details[ $environment_url ][ $idp_id ]['test_config_attributes'] = maybe_unserialize( get_option( 'mo_saml_test_config_attrs' ) );
	}

	/**
	 * Map the SP metadata.
	 *
	 * @param Normalized_Migration_Model $normalized_model The normalized model.
	 * @return void
	 */
	private function map_sp_metadata( $normalized_model ) {
		$normalized_model->sp_metadata[ Utility::parse_environment_url( site_url() ) ] = array(
			'sp_base_url'               => get_option( 'mo_saml_sp_base_url', home_url() ),
			'sp_entity_id'              => get_option( 'mo_saml_sp_entity_id', home_url() . Constants::SP_ENTITY_ID ),
			'public_key'                => get_option( 'mo_saml_current_cert' ),
			'private_key'               => get_option( 'mo_saml_current_cert_private_key' ),
			'is_custom_certificate'     => false,
			'organization_name'         => Constants::DEFAULT_ORGANIZATION_DETAILS['name'],
			'organization_display_name' => Constants::DEFAULT_ORGANIZATION_DETAILS['name'],
			'organization_url'          => Constants::DEFAULT_ORGANIZATION_DETAILS['url'],
			'technical_person_name'     => Constants::DEFAULT_ORGANIZATION_DETAILS['name'],
			'technical_person_email'    => Constants::DEFAULT_ORGANIZATION_DETAILS['email'],
			'support_person_name'       => Constants::DEFAULT_ORGANIZATION_DETAILS['name'],
			'support_person_email'      => Constants::DEFAULT_ORGANIZATION_DETAILS['email'],
		);
	}

	/**
	 * Map the subsites.
	 *
	 * @param Normalized_Migration_Model $normalized_model The normalized model.
	 * @return void
	 */
	private function map_subsites( $normalized_model ) {
		$normalized_model->subsites[ Utility::parse_environment_url( site_url() ) ] = array(
			'blog_id'  => 1,
			'site_url' => site_url(),
		);
	}

	/**
	 * Map the attribute mapping.
	 *
	 * @param Normalized_Migration_Model $normalized_model The normalized model.
	 * @return void
	 */
	private function map_attribute_mapping( $normalized_model ) {
		$idp_id = isset( $normalized_model->idp_details[ Utility::parse_environment_url( site_url() ) ] ) ? array_key_first( $normalized_model->idp_details[ Utility::parse_environment_url( site_url() ) ] ) : null;
		if ( ! $idp_id ) {
			return;
		}
		$normalized_model->attribute_mapping[ Utility::parse_environment_url( site_url() ) ][ $idp_id ] = array(
			'user_name'                  => get_option( 'saml_am_username' ),
			'email'                      => get_option( 'saml_am_email' ),
			'first_name'                 => get_option( 'saml_am_first_name' ),
			'last_name'                  => get_option( 'saml_am_last_name' ),
			'display_name'               => get_option( 'saml_am_display_name' ),
			'nick_name'                  => get_option( 'saml_am_nickname' ),
			'do_not_update_display_name' => Migration_Helper::map_value( 'on_to_checked', get_option( 'saml_am_update_display_name' ) ),
		);

		$custom_attributes = maybe_unserialize( get_option( 'mo_saml_custom_attrs_mapping' ) );
		if ( ! empty( $custom_attributes ) && is_array( $custom_attributes ) ) {
			$normalized_model->attribute_mapping[ Utility::parse_environment_url( site_url() ) ][ $idp_id ]['custom_attributes'] = $custom_attributes;
		}
		$custom_attributes_to_display = maybe_unserialize( get_option( 'saml_show_user_attribute' ) );
		if ( ! empty( $custom_attributes_to_display ) && is_array( $custom_attributes_to_display ) ) {
			$normalized_model->attribute_mapping[ Utility::parse_environment_url( site_url() ) ][ $idp_id ]['custom_attributes_to_display'] = $custom_attributes_to_display;
		}
	}

	/**
	 * Map the roles.
	 *
	 * @param Normalized_Migration_Model $normalized_model The normalized model.
	 * @return void
	 */
	private function map_role_mapping( $normalized_model ) {
		$idp_id = isset( $normalized_model->idp_details[ Utility::parse_environment_url( site_url() ) ] ) ? array_key_first( $normalized_model->idp_details[ Utility::parse_environment_url( site_url() ) ] ) : null;
		if ( ! $idp_id ) {
			return;
		}
		$role_mapping = maybe_unserialize( get_option( 'saml_am_role_mapping' ) );
		$normalized_model->role_mapping[ Utility::parse_environment_url( site_url() ) ][ $idp_id ] = ! empty( $role_mapping ) && is_array( $role_mapping ) ? $role_mapping : array();
	}

	/**
	 * Map the SSO settings.
	 *
	 * @param Normalized_Migration_Model $normalized_model The normalized model.
	 * @return void
	 */
	private function map_sso_settings( $normalized_model ) {
		$this->map_idp_specific_sso_settings( $normalized_model, Utility::parse_environment_url( site_url() ) );
		$this->map_default_idp_sso_settings( $normalized_model, Utility::parse_environment_url( site_url() ) );
	}

	/**
	 * Map the IDP specific SSO settings.
	 *
	 * @param Normalized_Migration_Model $normalized_model The normalized model.
	 * @param string                     $site_url The site URL.
	 * @return void
	 */
	private function map_idp_specific_sso_settings( $normalized_model, $site_url ) {
		$idp_id = isset( $normalized_model->idp_details[ $site_url ] ) ? array_key_first( $normalized_model->idp_details[ $site_url ] ) : null;
		if ( ! $idp_id ) {
			return;
		}

		$create_new_user       = get_option( 'saml_am_assign_default_role' );
		$assign_none_role      = get_option( 'saml_am_dont_allow_unlisted_user_role' );
		$default_role          = get_option( 'saml_am_default_user_role', get_option( 'default_role', 'subscriber' ) );
		$dont_create_new_users = get_option( 'mo_saml_dont_create_user_if_role_not_mapped', 'checked' );

		$create_user           = 'checked' === $create_new_user || 'checked' === $assign_none_role || 'checked' !== $dont_create_new_users ? 'checked' : '';
		$update_existing_user  = 'checked' === $assign_none_role ? 'checked' : '';
		$default_role_new      = $assign_none_role ? 'none' : $default_role;
		$default_role_existing = $assign_none_role ? 'none' : $default_role;

		$normalized_model->sso_settings[ $site_url ][ $idp_id ] = array(
			'group_attribute_name'              => get_option( 'saml_am_group_name' ),
			'apply_role_mapping_to_admin'       => Migration_Helper::map_value( 'on_to_checked', get_option( 'saml_am_apply_role_to_admin' ) ),
			'create_new_user'                   => $create_user,
			'update_existing_user'              => $update_existing_user,
			'default_role_existing'             => $default_role_existing,
			'default_role_new'                  => $default_role_new,
			'role_assignment_settings_recorded' => true,
		);

		$normalized_model->sso_settings[ $site_url ][ $idp_id ] = array_merge(
			$normalized_model->sso_settings[ $site_url ][ $idp_id ],
			array(
				'do_not_create_new_users'              => get_option( 'saml_am_dont_create_new_user' ),
				'do_not_update_existing_user_roles'    => get_option( 'saml_am_dont_update_existing_user_role' ),
				'whitelist_existing_users_roles'       => get_option( 'mo_saml_whitelist_existing_users_roles' ),
				'whitelisted_roles'                    => get_option( 'mo_saml_whitelisted_roles' ),
				'allow_deny_idp_attribute_toggle'      => get_option( 'saml_am_dont_allow_user_tologin_create_with_given_groups' ),
				'attribute_restriction_group'          => get_option( 'mo_saml_attr_restriction' ),
				'attribute_restriction_value'          => get_option( 'mo_saml_restrict_users_with_groups' ),
				'allow_deny_idp_attribute'             => get_option( 'mo_saml_allow_deny_user_with_group_values' ),
				'allow_deny_user_domain_toggle'        => get_option( 'mo_saml_enable_domain_restriction_login' ),
				'allow_deny_user_domain_value'         => get_option( 'saml_am_email_domains' ),
				'allow_deny_user_domain_type'          => get_option( 'mo_saml_allow_deny_user_with_domain' ),
				'enable_regex_for_role_mapping'        => get_option( 'mo_saml_role_enable_regex' ),
				'attr_role_advanced_settings_recorded' => true,
			)
		);

		$legacy_add_sso_button = get_option( 'mo_saml_add_sso_button_wp' );
		if ( empty( $legacy_add_sso_button ) ) {
			$legacy_add_sso_button = get_option( 'mo_saml_add_button_wp_login' );
		}
		$sso_button_config = array(
			'enable_sso_button'       => Migration_Helper::map_value( 'true_to_checked', $legacy_add_sso_button ),
			'use_button_as_shortcode' => Migration_Helper::map_value( 'true_to_checked', get_option( 'mo_saml_use_button_as_shortcode' ) ),
			'use_button_as_widget'    => Migration_Helper::map_value( 'true_to_checked', get_option( 'mo_saml_use_button_as_widget' ) ),
			'sso_button_config'       => array(
				'button_type'             => get_option( 'mo_saml_button_theme' ),
				'button_size'             => get_option( 'mo_saml_button_size' ),
				'button_width'            => get_option( 'mo_saml_button_width' ),
				'button_height'           => get_option( 'mo_saml_button_height' ),
				'button_curve'            => get_option( 'mo_saml_button_curve' ),
				'button_text'             => get_option( 'mo_saml_button_text' ),
				'button_color'            => get_option( 'mo_saml_button_color' ),
				'font_size'               => get_option( 'mo_saml_font_size' ),
				'font_color'              => get_option( 'mo_saml_font_color' ),
				'button_position'         => get_option( 'sso_button_login_form_position' ),
				'use_button_as_shortcode' => Migration_Helper::map_value( 'true_to_checked', get_option( 'mo_saml_use_button_as_shortcode' ) ),
				'use_button_as_widget'    => Migration_Helper::map_value( 'true_to_checked', get_option( 'mo_saml_use_button_as_widget' ) ),
				'idp_id'                  => $idp_id,

			),
		);

		$normalized_model->sso_settings[ $site_url ][ $idp_id ] = array_merge(
			$normalized_model->sso_settings[ $site_url ][ $idp_id ],
			$sso_button_config,
		);

		$widget_config = array(
			'widget_config' => array(
				'custom_login_text'    => get_option( 'mo_saml_custom_login_text' ),
				'custom_greeting_text' => get_option( 'mo_saml_custom_greeting_text' ),
				'greeting_name'        => get_option( 'mo_saml_greeting_name' ),
				'custom_logout_text'   => get_option( 'mo_saml_custom_logout_text' ),
			),
		);

		$normalized_model->sso_settings[ $site_url ][ $idp_id ] = array_merge(
			$normalized_model->sso_settings[ $site_url ][ $idp_id ],
			$widget_config,
		);

		$absolute_relay_state = get_option( 'mo_saml_send_absolute_relay_state' );
		$login_relay_state    = get_option( 'mo_saml_relay_state', '' );
		$logout_relay_state   = get_option( 'mo_saml_logout_relay_state', '' );

		$login_relay_mapped  = '';
		$logout_relay_mapped = '';
		if ( '' !== $login_relay_state ) {
			$login_relay_mapped = $absolute_relay_state ? $login_relay_state : site_url() . $login_relay_state;
		}
		if ( '' !== $logout_relay_state ) {
			$logout_relay_mapped = $absolute_relay_state ? $logout_relay_state : site_url() . $logout_relay_state;
		}

		$normalized_model->sso_settings[ $site_url ][ $idp_id ] = array_merge(
			$normalized_model->sso_settings[ $site_url ][ $idp_id ],
			array(
				'login_relay_state'  => $login_relay_mapped,
				'logout_relay_state' => $logout_relay_mapped,
			)
		);
	}

	/**
	 * Map the default IDP SSO settings.
	 *
	 * @param Normalized_Migration_Model $normalized_model The normalized model.
	 * @param string                     $site_url The site URL.
	 * @return void
	 */
	private function map_default_idp_sso_settings( $normalized_model, $site_url ) {
		$site_auto_redirection_option = '';
		 if ( get_option( 'mo_saml_registered_only_access' ) ) {
			$site_auto_redirection_option = 'default_idp';
		}elseif ( get_option( 'mo_saml_redirect_to_wp_login' ) ) {
			$site_auto_redirection_option = 'wp_login';
		}

		$enable_auto_redirect = get_option( 'mo_saml_registered_only_access', '' );
		if ( empty( $enable_auto_redirect ) && get_option( 'mo_saml_redirect_to_wp_login' ) ) {
			$enable_auto_redirect = get_option( 'mo_saml_redirect_to_wp_login' );
		}

		$normalized_model->sso_settings[ $site_url ]['DEFAULT'] = array(
			'enable_site_auto_redirect'     => Migration_Helper::map_value( 'true_to_checked', $enable_auto_redirect ),
			'site_auto_redirection_option'  => $site_auto_redirection_option,
			'enable_rss_feed_access'        => Migration_Helper::map_value( 'true_to_checked', get_option( 'mo_saml_enable_rss_access', '' ) ),
			'enable_force_authentication'   => Migration_Helper::map_value( 'true_to_checked', get_option( 'mo_saml_force_authentication', '' ) ),
			'redirect_from_wp_login'        => Migration_Helper::map_value( 'true_to_checked', get_option( 'mo_saml_enable_login_redirect', '' ) ),
			'enable_backdoor_url_login'     => Migration_Helper::map_value( 'true_to_checked', get_option( 'mo_saml_allow_wp_signin', '' ) ),
			'backdoor_url'                  => get_option( 'mo_saml_backdoor_url', 'false' ),
			'sso_show_user'                 => Migration_Helper::map_value( 'on_to_checked', get_option( 'mo_saml_sso_show_user', '' ) ),
			'account_creation_disabled_msg' => get_option( 'mo_saml_account_creation_disabled_msg', '' ),
			'restricted_domain_error_msg'   => get_option( 'mo_saml_restricted_domain_error_msg', '' ),
		);
	}
}
