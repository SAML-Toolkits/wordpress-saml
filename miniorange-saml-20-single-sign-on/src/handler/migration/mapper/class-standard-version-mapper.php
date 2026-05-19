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
class Standard_Version_Mapper implements Legacy_Version_Mapper {

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
		$normalized_model->global_options['mosaml_keep_settings_on_deletion'] = Migration_Helper::map_value( 'true_to_checked', get_option( 'mo_saml_keep_settings_on_deletion' ) );
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
			'user_name'    => get_option( 'saml_am_username' ),
			'email'        => get_option( 'saml_am_email' ),
			'first_name'   => get_option( 'saml_am_first_name' ),
			'last_name'    => get_option( 'saml_am_last_name' ),
			'display_name' => get_option( 'saml_am_display_name' ),
		);
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
		$normalized_model->role_mapping[ Utility::parse_environment_url( site_url() ) ][ $idp_id ] = array();
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

		$default_role = get_option( 'saml_am_default_user_role', get_option( 'default_role', 'subscriber' ) );

		$normalized_model->sso_settings[ $site_url ][ $idp_id ] = array(
			'create_new_user'                   => 'checked',
			'update_existing_user'              => Migration_Helper::map_value( 'unchecked_to_checked', get_option( 'saml_am_dont_update_existing_user_role' ) ),
			'default_role_existing'             => $default_role,
			'default_role_new'                  => $default_role,
			'role_assignment_settings_recorded' => true,
		);

		$sso_button_config = array(
			'enable_sso_button' => Migration_Helper::map_value( 'true_to_checked', get_option( 'mo_saml_add_sso_button_wp' ) ),
			'sso_button_config' => array(
				'button_type'             => 'longbutton',
				'button_size'             => '50',
				'button_width'            => '270',
				'button_height'           => '30',
				'button_curve'            => '3',
				'button_color'            => '#2271b1',
				'font_size'               => '14',
				'font_color'              => '#ffffff',
				'button_position'         => 'above',
				'button_text'             => $normalized_model->idp_details[ $site_url ][ $idp_id ]['idp_name'],
				'use_button_as_shortcode' => '',
				'use_button_as_widget'    => '',
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

		$normalized_model->sso_settings[ $site_url ][ $idp_id ] = array_merge(
			$normalized_model->sso_settings[ $site_url ][ $idp_id ],
			array(
				'login_relay_state' => get_option( 'mo_saml_relay_state' ),
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
		$normalized_model->sso_settings[ $site_url ]['DEFAULT'] = array(
			'enable_site_auto_redirect'    => Migration_Helper::map_value( 'true_to_checked', get_option( 'mo_saml_registered_only_access', '' ) ),
			'site_auto_redirection_option' => 'default_idp',
			'enable_rss_feed_access'       => Migration_Helper::map_value( 'true_to_checked', get_option( 'mo_saml_enable_rss_access', '' ) ),
			'enable_force_authentication'  => Migration_Helper::map_value( 'true_to_checked', get_option( 'mo_saml_force_authentication', '' ) ),
			'redirect_from_wp_login'       => Migration_Helper::map_value( 'true_to_checked', get_option( 'mo_saml_enable_login_redirect', '' ) ),
			'enable_backdoor_url_login'    => Migration_Helper::map_value( 'true_to_checked', get_option( 'mo_saml_allow_wp_signin', '' ) ),
			'backdoor_url'                 => get_option( 'mo_saml_backdoor_url', 'false' ),
		);
	}
}
