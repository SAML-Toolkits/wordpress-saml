<?php
/**
 * Enterprise Version Mapper.
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
use MOSAML\SRC\Constant\Plugin_Files_Constants;

/**
 * Enterprise Version Mapper.
 */
class Enterprise_Version_Mapper implements Legacy_Version_Mapper {

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
		update_option( Constants::ENABLE_MULTIPLE_ENVIRONMENTS_OPTION_NAME, get_option( 'mo_enable_multiple_licenses', '' ) );
		require_once Plugin_Files_Constants::HANDLER_MIGRATION_MAPPER_ENVIRONMENT_OBJECT;
		$environments_object = maybe_unserialize( get_option( 'mo_saml_environment_objects' ) );
		if ( ! empty( $environments_object ) ) {
			$selected_environment = get_option( 'mo_saml_selected_environment' );
			foreach ( $environments_object as $environment_name => $environment_object ) {
				$environment_url_key = Utility::parse_environment_url( $environment_object->getWpSiteUrl() );
				$normalized_model->environments[ $environment_url_key ] = array(
					'environment_name' => $environment_name,
					'environment_url'  => $environment_url_key,
					'is_selected'      => $environment_name === $selected_environment,
				);
			}
			return;
		}
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
		require_once Plugin_Files_Constants::HANDLER_MIGRATION_MAPPER_ENVIRONMENT_OBJECT;
		$environments_object = maybe_unserialize( get_option( 'mo_saml_environment_objects' ) );
		if ( ! empty( $environments_object ) ) {
			foreach ( $environments_object as $environment_object ) {
				$environment_url_key = Utility::parse_environment_url( $environment_object->getWpSiteUrl() );
				$all_idp_id = Utility::generate_idp_id();
				$normalized_model->idp_details[ $environment_url_key ][ $all_idp_id ] = array(
					'idp_id'          => $all_idp_id,
					'idp_name'        => 'All IDPs',
					'entity_id'       => 'All IDPs',
					'sso_url'         => 'All IDPs',
					'slo_url'         => 'All IDPs',
					'idp_certificate' => 'All IDPs',
				);
				$plugin_settings = $environment_object->getPluginSettings();
				$idp_details     = isset( $plugin_settings['saml_identity_providers'] ) ? $plugin_settings['saml_identity_providers'] : array();
				if ( empty( $idp_details ) ) {
					continue;
				}
				$default_idp = $plugin_settings['saml_default_idp'];
				foreach ( $idp_details as $idp_id => $idp_config ) {
					$normalized_model->idp_details[ $environment_url_key ][ $idp_id ] = array(
						'idp_id'                  => $idp_id,
						'idp_name'                => $idp_config['idp_display_name'],
						'entity_id'               => $idp_config['idp_entity_id'],
						'sso_url'                 => $idp_config['sso_url'],
						'slo_url'                 => isset( $idp_config['slo_url'] ) ? $idp_config['slo_url'] : '',
						'idp_certificate'         => $idp_config['x509_certificate'],
						'slo_response_url'        => $idp_config['slo_response_url'],
						'password_reset_url'      => isset( $idp_config['saml_pw_reset_url'] ) ? $idp_config['saml_pw_reset_url'] : '',
						'character_encoding'      => isset( $idp_config['mo_saml_encoding_enabled'] ) ? $idp_config['mo_saml_encoding_enabled'] : 'checked',
						'assertion_time_validity' => isset( $idp_config['mo_saml_assertion_time_validity'] ) ? $idp_config['mo_saml_assertion_time_validity'] : 'checked',
						'sign_sso_slo_request'    => $idp_config['request_signed'],
						'sso_binding'             => isset( $idp_config['sso_binding_type'] ) ? $idp_config['sso_binding_type'] : 'HttpRedirect',
						'slo_binding'             => isset( $idp_config['slo_binding_type'] ) ? $idp_config['slo_binding_type'] : 'HttpRedirect',
						'sp_entity_id'            => isset( $idp_config['saml_sp_entity_id'] ) ? $idp_config['saml_sp_entity_id'] : home_url() . Constants::SP_ENTITY_ID,
						'name_id_format'          => 'urn:oasis:names:tc:SAML:' . ( ! empty( $idp_config['nameid_format'] ) ? $idp_config['nameid_format'] : '1.1:nameid-format:unspecified' ),
						'default_idp'             => $idp_id === $default_idp,
						'status'                  => $idp_config['enable_idp'] ? 'active' : 'inactive',
						'saml_request'            => $idp_config['saml_request'],
						'saml_response'           => $idp_config['saml_response'],
						'test_config_attributes'  => isset( $plugin_settings['mo_saml_test_config_attrs'][ $idp_id ] ) ? maybe_unserialize( $plugin_settings['mo_saml_test_config_attrs'][ $idp_id ] ) : array(),
					);
				}

				$sync_metadata_details = isset( $plugin_settings['saml_metadata_url_for_sync'] ) ? $plugin_settings['saml_metadata_url_for_sync'] : array();
				foreach ( $sync_metadata_details as $idp_id => $sync_metadata_detail ) {
					if ( ! isset( $normalized_model->idp_details[ $environment_url_key ][ $idp_id ] ) || empty( $normalized_model->idp_details[ $environment_url_key ][ $idp_id ] ) ) {
						continue;
					}
					$normalized_model->idp_details[ $environment_url_key ][ $idp_id ]['sync_metadata']         = true;
					$normalized_model->idp_details[ $environment_url_key ][ $idp_id ]['metadata_url']          = $sync_metadata_detail['metadata_url'];
					$normalized_model->idp_details[ $environment_url_key ][ $idp_id ]['sync_time_interval']    = $sync_metadata_detail['sync_interval'];
					$normalized_model->idp_details[ $environment_url_key ][ $idp_id ]['sync_only_certificate'] = $sync_metadata_detail['sync_certificate_metadata'];
				}
			}
			return;
		}
		$idp_details     = maybe_unserialize( get_option( 'saml_identity_providers' ) );
		$environment_url = Utility::parse_environment_url( site_url() );
		if ( ! empty( $idp_details ) ) {
			$default_idp = get_option( 'saml_default_idp' );
			foreach ( $idp_details as $idp_id => $idp_config ) {
				$normalized_model->idp_details[ $environment_url ][ $idp_id ] = array(
					'idp_id'                  => $idp_id,
					'idp_name'                => $idp_config['idp_display_name'],
					'entity_id'               => $idp_config['idp_entity_id'],
					'sso_url'                 => $idp_config['sso_url'],
					'slo_url'                 => $idp_config['slo_url'],
					'idp_certificate'         => $idp_config['x509_certificate'],
					'slo_response_url'        => $idp_config['slo_response_url'],
					'password_reset_url'      => isset( $idp_config['saml_pw_reset_url'] ) ? $idp_config['saml_pw_reset_url'] : '',
					'character_encoding'      => isset( $idp_config['mo_saml_encoding_enabled'] ) ? $idp_config['mo_saml_encoding_enabled'] : 'checked',
					'assertion_time_validity' => isset( $idp_config['mo_saml_assertion_time_validity'] ) ? $idp_config['mo_saml_assertion_time_validity'] : 'checked',
					'sign_sso_slo_request'    => $idp_config['request_signed'],
					'sso_binding'             => isset( $idp_config['sso_binding_type'] ) ? $idp_config['sso_binding_type'] : 'HttpRedirect',
					'slo_binding'             => isset( $idp_config['slo_binding_type'] ) ? $idp_config['slo_binding_type'] : 'HttpRedirect',
					'sp_entity_id'            => isset( $idp_config['saml_sp_entity_id'] ) ? $idp_config['saml_sp_entity_id'] : home_url() . Constants::SP_ENTITY_ID,
					'name_id_format'          => 'urn:oasis:names:tc:SAML:' . $idp_config['nameid_format'],
					'default_idp'             => $idp_id === $default_idp,
					'status'                  => $idp_config['enable_idp'] ? 'active' : 'inactive',
					'saml_request'            => $idp_config['saml_request'],
					'saml_response'           => $idp_config['saml_response'],
				);
			}
		}

		$sync_metadata_details = maybe_unserialize( get_option( 'saml_metadata_url_for_sync' ) );
		if ( ! empty( $sync_metadata_details ) && is_array( $sync_metadata_details ) ) {
			foreach ( $sync_metadata_details as $idp_id => $sync_metadata_detail ) {
				if ( ! isset( $normalized_model->idp_details[ $environment_url ][ $idp_id ] ) || empty( $normalized_model->idp_details[ $environment_url ][ $idp_id ] ) ) {
					continue;
				}
				$normalized_model->idp_details[ $environment_url ][ $idp_id ]['sync_metadata']         = true;
				$normalized_model->idp_details[ $environment_url ][ $idp_id ]['metadata_url']          = $sync_metadata_detail['metadata_url'];
				$normalized_model->idp_details[ $environment_url ][ $idp_id ]['sync_time_interval']    = $sync_metadata_detail['sync_interval'];
				$normalized_model->idp_details[ $environment_url ][ $idp_id ]['sync_only_certificate'] = $sync_metadata_detail['sync_certificate_metadata'];
			}
		}

		$test_config_attributes = maybe_unserialize( get_option( 'mo_saml_test_config_attrs' ) );
		if ( ! empty( $test_config_attributes ) && is_array( $test_config_attributes ) ) {
			foreach ( $test_config_attributes as $idp_id => $test_config_attribute ) {
				if ( ! isset( $normalized_model->idp_details[ $environment_url ][ $idp_id ] ) || empty( $normalized_model->idp_details[ $environment_url ][ $idp_id ] ) ) {
					continue;
				}
				$normalized_model->idp_details[ $environment_url ][ $idp_id ]['test_config_attributes'] = $test_config_attribute;
			}
		}
	}

	/**
	 * Map the SP metadata.
	 *
	 * @param Normalized_Migration_Model $normalized_model The normalized model.
	 * @return void
	 */
	private function map_sp_metadata( $normalized_model ) {
		require_once Plugin_Files_Constants::HANDLER_MIGRATION_MAPPER_ENVIRONMENT_OBJECT;
		$organization_name         = get_option( 'mo_saml_metadata_org_name' );
		$organization_display_name = get_option( 'mo_saml_metadata_org_display_name' );
		$organization_url          = get_option( 'mo_saml_metadata_org_url' );
		$technical_person_name     = get_option( 'mo_saml_metadata_tech_person_name' );
		$technical_person_email    = get_option( 'mo_saml_metadata_tech_person_email' );
		$support_person_name       = get_option( 'mo_saml_metadata_support_person_name' );
		$support_person_email      = get_option( 'mo_saml_metadata_support_person_email' );
		if ( empty( $organization_name ) ) {
			$organization_name = Constants::DEFAULT_ORGANIZATION_DETAILS['name'];
		}
		if ( empty( $organization_display_name ) ) {
			$organization_display_name = Constants::DEFAULT_ORGANIZATION_DETAILS['name'];
		}
		if ( empty( $organization_url ) ) {
			$organization_url = Constants::DEFAULT_ORGANIZATION_DETAILS['url'];
		}
		if ( empty( $technical_person_name ) ) {
			$technical_person_name = Constants::DEFAULT_ORGANIZATION_DETAILS['name'];
		}
		if ( empty( $technical_person_email ) ) {
			$technical_person_email = Constants::DEFAULT_ORGANIZATION_DETAILS['email'];
		}
		if ( empty( $support_person_name ) ) {
			$support_person_name = Constants::DEFAULT_ORGANIZATION_DETAILS['name'];
		}
		if ( empty( $support_person_email ) ) {
			$support_person_email = Constants::DEFAULT_ORGANIZATION_DETAILS['email'];
		}

		$environments_object = maybe_unserialize( get_option( 'mo_saml_environment_objects' ) );
		if ( ! empty( $environments_object ) ) {
			foreach ( $environments_object as $environment_object ) {
				$plugin_settings     = $environment_object->getPluginSettings();
				$environment_url_key = Utility::parse_environment_url( $environment_object->getWpSiteUrl() );

				$normalized_model->sp_metadata[ $environment_url_key ] = array(
					'sp_base_url'               => $plugin_settings['mo_saml_sp_base_url'] ?? $environment_object->getWpSiteUrl(),
					'sp_entity_id'              => $plugin_settings['mo_saml_sp_entity_id'] ?? $environment_object->getWpSiteUrl() . Constants::SP_ENTITY_ID,
					'public_key'                => get_option( 'mo_saml_current_cert' ),
					'private_key'               => get_option( 'mo_saml_current_cert_private_key' ),
					'is_custom_certificate'     => false,
					'organization_name'         => $organization_name,
					'organization_display_name' => $organization_display_name,
					'organization_url'          => $organization_url,
					'technical_person_name'     => $technical_person_name,
					'technical_person_email'    => $technical_person_email,
					'support_person_name'       => $support_person_name,
					'support_person_email'      => $support_person_email,
				);
			}
			return;
		}
		$normalized_model->sp_metadata[ Utility::parse_environment_url( site_url() ) ] = array(
			'sp_base_url'               => home_url(),
			'sp_entity_id'              => home_url() . Constants::SP_ENTITY_ID,
			'public_key'                => get_option( 'mo_saml_current_cert' ),
			'private_key'               => get_option( 'mo_saml_current_cert_private_key' ),
			'is_custom_certificate'     => false,
			'organization_name'         => $organization_name,
			'organization_display_name' => $organization_display_name,
			'organization_url'          => $organization_url,
			'technical_person_name'     => $technical_person_name,
			'technical_person_email'    => $technical_person_email,
			'support_person_name'       => $support_person_name,
			'support_person_email'      => $support_person_email,
		);
	}

	/**
	 * Map the subsites.
	 *
	 * @param Normalized_Migration_Model $normalized_model The normalized model.
	 * @return void
	 */
	private function map_subsites( $normalized_model ) {
		require_once Plugin_Files_Constants::HANDLER_MIGRATION_MAPPER_ENVIRONMENT_OBJECT;
		$environments_object = maybe_unserialize( get_option( 'mo_saml_environment_objects' ) );
		if ( ! empty( $environments_object ) ) {
			foreach ( $environments_object as $environment_object ) {
				$environment_url_key = Utility::parse_environment_url( $environment_object->getWpSiteUrl() );
				$normalized_model->subsites[ $environment_url_key ] = array(
					'blog_id'  => 1,
					'site_url' => $environment_object->getWpSiteUrl(),
				);
			}
			return;
		}
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
		require_once Plugin_Files_Constants::HANDLER_MIGRATION_MAPPER_ENVIRONMENT_OBJECT;
		$environments_object = maybe_unserialize( get_option( 'mo_saml_environment_objects' ) );
		if ( ! empty( $environments_object ) ) {
			foreach ( $environments_object as  $environment_object ) {
				$environment_url_key = Utility::parse_environment_url( $environment_object->getWpSiteUrl() );
				$plugin_settings = $environment_object->getPluginSettings();

				$attribute_mappings = isset( $plugin_settings['mo_saml_attribute_mapping'] ) ? $plugin_settings['mo_saml_attribute_mapping'] : array();
				foreach ( $attribute_mappings as $idp_id => $attribute_mapping ) {
					$normalized_model->attribute_mapping[$environment_url_key][ $idp_id ] = array(
						'user_name'                  => $attribute_mapping['username'],
						'email'                      => $attribute_mapping['email'],
						'first_name'                 => $attribute_mapping['first_name'],
						'last_name'                  => $attribute_mapping['last_name'],
						'display_name'               => $attribute_mapping['display_name'],
						'nick_name'                  => $attribute_mapping['nick_name'],
						'do_not_update_display_name' => isset( $attribute_mapping['do_not_update_display_name'] ) ? $attribute_mapping['do_not_update_display_name'] : '',
					);
				}

				$custom_attributes = isset( $plugin_settings['mo_saml_custom_attrs_mapping'] ) ? $plugin_settings['mo_saml_custom_attrs_mapping'] : array();
				foreach ( $custom_attributes as $idp_id => $custom_attribute ) {
					$normalized_model->attribute_mapping[$environment_url_key][ $idp_id ]['custom_attributes'] = $custom_attribute;
				}

				$custom_attributes_to_display = isset( $plugin_settings['saml_attrs_to_display_idp'] ) ? $plugin_settings['saml_attrs_to_display_idp'] : array();
				foreach ( $custom_attributes_to_display as $idp_id => $custom_attribute_to_display ) {
					$normalized_model->attribute_mapping[$environment_url_key][ $idp_id ]['custom_attributes_to_display'] = $custom_attribute_to_display;
				}
			}
			return;
		}
		$attribute_mappings = maybe_unserialize( get_option( 'mo_saml_attribute_mapping' ) );
		if ( ! empty( $attribute_mappings ) && is_array( $attribute_mappings ) ) {
			foreach ( $attribute_mappings as $idp_id => $attribute_mapping ) {
				$normalized_model->attribute_mapping[ Utility::parse_environment_url( site_url() ) ][ $idp_id ] = array(
					'user_name'                  => $attribute_mapping['username'],
					'email'                      => $attribute_mapping['email'],
					'first_name'                 => $attribute_mapping['first_name'],
					'last_name'                  => $attribute_mapping['last_name'],
					'display_name'               => $attribute_mapping['display_name'],
					'nick_name'                  => $attribute_mapping['nick_name'],
					'do_not_update_display_name' => isset( $attribute_mapping['do_not_update_display_name'] ) ? $attribute_mapping['do_not_update_display_name'] : '',
				);
			}
		}
		$custom_attributes = maybe_unserialize( get_option( 'mo_saml_custom_attrs_mapping' ) );
		if ( ! empty( $custom_attributes ) && is_array( $custom_attributes ) ) {
			foreach ( $custom_attributes as $idp_id => $custom_attribute ) {
				$normalized_model->attribute_mapping[ $idp_id ]['custom_attributes'] = $custom_attribute;
			}
		}
		$custom_attributes_to_display = maybe_unserialize( get_option( 'saml_attrs_to_display_idp' ) );
		if ( ! empty( $custom_attributes_to_display ) && is_array( $custom_attributes_to_display ) ) {
			foreach ( $custom_attributes_to_display as $idp_id => $custom_attribute_to_display ) {
				$normalized_model->attribute_mapping[ Utility::parse_environment_url( site_url() ) ][ $idp_id ]['custom_attributes_to_display'] = $custom_attribute_to_display;
			}
		}
	}

	/**
	 * Map the roles.
	 *
	 * @param Normalized_Migration_Model $normalized_model The normalized model.
	 * @return void
	 */
	private function map_role_mapping( $normalized_model ) {
		require_once Plugin_Files_Constants::HANDLER_MIGRATION_MAPPER_ENVIRONMENT_OBJECT;
		$environments_object = maybe_unserialize( get_option( 'mo_saml_environment_objects' ) );
		if ( ! empty( $environments_object ) ) {
			foreach ( $environments_object as $environment_object ) {
				$plugin_settings     = $environment_object->getPluginSettings();
				$environment_url_key = Utility::parse_environment_url( $environment_object->getWpSiteUrl() );
				$normalized_model->role_mapping[ $environment_url_key ] = isset( $plugin_settings['mo_saml_configured_role_values'] ) ? $plugin_settings['mo_saml_configured_role_values'] : array();
			}
			return;
		}
		$role_mapping = maybe_unserialize( get_option( 'mo_saml_configured_role_values' ) );
		$normalized_model->role_mapping[ Utility::parse_environment_url( site_url() ) ] = ! empty( $role_mapping ) && is_array( $role_mapping ) ? $role_mapping : array();
	}

	/**
	 * Map the SSO settings.
	 *
	 * @param Normalized_Migration_Model $normalized_model The normalized model.
	 * @return void
	 */
	private function map_sso_settings( $normalized_model ) {
		require_once Plugin_Files_Constants::HANDLER_MIGRATION_MAPPER_ENVIRONMENT_OBJECT;
		$environments_object = maybe_unserialize( get_option( 'mo_saml_environment_objects' ) );
		if ( ! empty( $environments_object ) ) {
			foreach ( $environments_object as $environment_object ) {
				$plugin_settings     = $environment_object->getPluginSettings();
				$environment_url_key = Utility::parse_environment_url( $environment_object->getWpSiteUrl() );
				$this->map_idp_specific_sso_settings( $normalized_model, $plugin_settings, $environment_url_key );
				$this->map_default_idp_sso_settings( $normalized_model, $plugin_settings, $environment_url_key );
			}
			return;
		}
		$fallback_env_key = Utility::parse_environment_url( site_url() );
		$this->map_idp_specific_sso_settings( $normalized_model, null, $fallback_env_key );
		$this->map_default_idp_sso_settings( $normalized_model, null, $fallback_env_key );
	}

	/**
	 * Map the IDP specific SSO settings.
	 *
	 * @param Normalized_Migration_Model $normalized_model The normalized model.
	 * @param array                      $plugin_settings The plugin settings.
	 * @param string                     $site_url The site URL.
	 * @return void
	 */
	private function map_idp_specific_sso_settings( $normalized_model, $plugin_settings, $site_url ) {
		$role_mapping_configurations = isset( $plugin_settings['mo_saml_role_mapping_configurations'] ) ? $plugin_settings['mo_saml_role_mapping_configurations'] : array();
		if ( ! $plugin_settings ) {
			$role_mapping_configurations = maybe_unserialize( get_option( 'mo_saml_role_mapping_configurations' ) );
		}
		if ( empty( $role_mapping_configurations ) || ! is_array( $role_mapping_configurations ) ) {
			$role_mapping_configurations = array();
		}
		foreach ( $role_mapping_configurations as $idp_id => $role_mapping_configuration ) {
			if ( ! isset( $normalized_model->sso_settings[ $site_url ][ $idp_id ] ) || ! array( $normalized_model->sso_settings[ $site_url ][ $idp_id ] ) ) {
				$normalized_model->sso_settings[ $site_url ][ $idp_id ] = array();
			}
			$normalized_model->sso_settings[ $site_url ][ $idp_id ] = array_merge(
				$normalized_model->sso_settings[ $site_url ][ $idp_id ],
				array(
					'group_attribute_name'               => isset( $role_mapping_configuration['group_name'] ) ? $role_mapping_configuration['group_name'] : '',
					'apply_role_mapping_to_admin'        => isset( $role_mapping_configuration['apply_role_to_admin'] ) ? $role_mapping_configuration['apply_role_to_admin'] : '',
					'create_new_user'                    => isset( $role_mapping_configuration['create_new_user'] ) ? $role_mapping_configuration['create_new_user'] : 'checked',
					'update_existing_user'               => isset( $role_mapping_configuration['update_existing_user'] ) ? $role_mapping_configuration['update_existing_user'] : '',
					'default_role_existing'              => isset( $role_mapping_configuration['default_role_for_existing_users'] ) ? $role_mapping_configuration['default_role_for_existing_users'] : 'subscriber',
					'default_role_new'                   => isset( $role_mapping_configuration['default_role_for_new_users'] ) ? $role_mapping_configuration['default_role_for_new_users'] : 'subscriber',
					'role_assignment_settings_recorded'  => true,
				)
			);
		}

		$attribute_role_advanced_settings = isset( $plugin_settings['mo_saml_attr_role_advanced_settings'] ) ? $plugin_settings['mo_saml_attr_role_advanced_settings'] : array();
		if ( ! $plugin_settings ) {
			$attribute_role_advanced_settings = maybe_unserialize( get_option( 'mo_saml_attr_role_advanced_settings', array() ) );
		}
		if ( empty( $attribute_role_advanced_settings ) || ! is_array( $attribute_role_advanced_settings ) ) {
			$attribute_role_advanced_settings = array();
		}
		foreach ( $attribute_role_advanced_settings as $idp_id => $attribute_role_advanced_setting ) {
			if ( ! isset( $normalized_model->sso_settings[ $site_url ][ $idp_id ] ) || ! array( $normalized_model->sso_settings[ $site_url ][ $idp_id ] ) ) {
				$normalized_model->sso_settings[ $site_url ][ $idp_id ] = array();
			}
			$normalized_model->sso_settings[ $site_url ][ $idp_id ] = array_merge(
				$normalized_model->sso_settings[ $site_url ][ $idp_id ],
				array(
					'do_not_create_new_users'              => isset( $attribute_role_advanced_setting['do_not_create_new_users'] ) ? $attribute_role_advanced_setting['do_not_create_new_users'] : '',
					'do_not_update_existing_user_roles'    => isset( $attribute_role_advanced_setting['keep_existing_users_role'] ) ? $attribute_role_advanced_setting['keep_existing_users_role'] : '',
					'whitelist_existing_users_roles'       => isset( $attribute_role_advanced_setting['whitelist_existing_users_roles'] ) ? $attribute_role_advanced_setting['whitelist_existing_users_roles'] : '',
					'whitelisted_roles'                    => isset( $attribute_role_advanced_setting['whitelisted_roles'] ) ? $attribute_role_advanced_setting['whitelisted_roles'] : '',
					'allow_deny_idp_attribute_toggle'      => isset( $attribute_role_advanced_setting['allow_deny_user_attribute'] ) ? $attribute_role_advanced_setting['allow_deny_user_attribute'] : '',
					'attribute_restriction_group'          => isset( $attribute_role_advanced_setting['restricted_attribute'] ) ? $attribute_role_advanced_setting['restricted_attribute'] : '',
					'attribute_restriction_value'          => isset( $attribute_role_advanced_setting['restricted_attribute_values'] ) ? $attribute_role_advanced_setting['restricted_attribute_values'] : '',
					'allow_deny_idp_attribute'             => isset( $attribute_role_advanced_setting['allow_deny_attr_option'] ) ? $attribute_role_advanced_setting['allow_deny_attr_option'] : 'allow',
					'allow_deny_user_domain_toggle'        => isset( $attribute_role_advanced_setting['allow_deny_user_domain'] ) ? $attribute_role_advanced_setting['allow_deny_user_domain'] : '',
					'allow_deny_user_domain_value'         => isset( $attribute_role_advanced_setting['restricted_domains'] ) ? $attribute_role_advanced_setting['restricted_domains'] : '',
					'allow_deny_user_domain_type'          => isset( $attribute_role_advanced_setting['allow_deny_domain_option'] ) ? $attribute_role_advanced_setting['allow_deny_domain_option'] : 'allow',
					'enable_regex_for_role_mapping'        => isset( $attribute_role_advanced_setting['enable_regex'] ) ? $attribute_role_advanced_setting['enable_regex'] : '',
					'attr_role_advanced_settings_recorded' => true,
				)
			);
		}

		$sso_button_configurations = isset( $plugin_settings['saml_sso_button_idp'] ) ? $plugin_settings['saml_sso_button_idp'] : array();
		if ( ! $plugin_settings ) {
			$sso_button_configurations = maybe_unserialize( get_option( 'saml_sso_button_idp', array() ) );
		}
		if ( empty( $sso_button_configurations ) || ! is_array( $sso_button_configurations ) ) {
			$sso_button_configurations = array();
		}
		foreach ( $sso_button_configurations as $idp_id => $sso_button_configuration ) {
			$sso_button_config = array(
				'enable_sso_button'       => isset( $sso_button_configuration['add_button_wp_login'] ) ? Migration_Helper::map_value( 'true_to_checked', $sso_button_configuration['add_button_wp_login'] ) : '',
				'use_button_as_shortcode' => isset( $sso_button_configuration['use_button_as_shortcode'] ) ? Migration_Helper::map_value( 'true_to_checked', $sso_button_configuration['use_button_as_shortcode'] ) : '',
				'use_button_as_widget'    => isset( $sso_button_configuration['use_button_as_widget'] ) ? Migration_Helper::map_value( 'true_to_checked', $sso_button_configuration['use_button_as_widget'] ) : '',
				'sso_button_config'       => array(
					'button_type'             => $sso_button_configuration['button_type'],
					'button_size'             => $sso_button_configuration['button_size'],
					'button_width'            => $sso_button_configuration['button_width'],
					'button_height'           => $sso_button_configuration['button_height'],
					'button_curve'            => $sso_button_configuration['button_curve'],
					'button_text'             => $sso_button_configuration['button_text'],
					'button_color'            => $sso_button_configuration['button_color'],
					'font_size'               => $sso_button_configuration['font_size'],
					'font_color'              => $sso_button_configuration['font_color'],
					'button_position'         => $sso_button_configuration['button_position'],
					'use_button_as_shortcode' => isset( $sso_button_configuration['use_button_as_shortcode'] ) ? Migration_Helper::map_value( 'true_to_checked', $sso_button_configuration['use_button_as_shortcode'] ) : '',
					'use_button_as_widget'    => isset( $sso_button_configuration['use_button_as_widget'] ) ? Migration_Helper::map_value( 'true_to_checked', $sso_button_configuration['use_button_as_widget'] ) : '',
					'idp_id'                  => $idp_id,

				),
			);
			if ( ! isset( $normalized_model->sso_settings[ $site_url ][ $idp_id ] ) || ! array( $normalized_model->sso_settings[ $site_url ][ $idp_id ] ) ) {
				$normalized_model->sso_settings[ $site_url ][ $idp_id ] = array();
			}
			$normalized_model->sso_settings[ $site_url ][ $idp_id ] = array_merge(
				$normalized_model->sso_settings[ $site_url ][ $idp_id ],
				$sso_button_config,
			);
		}

		$identity_provider_configurations = isset( $plugin_settings['saml_identity_providers'] ) ? $plugin_settings['saml_identity_providers'] : array();
		if ( ! $plugin_settings ) {
			$identity_provider_configurations = maybe_unserialize( get_option( 'saml_identity_providers', array() ) );
		}
		if ( empty( $identity_provider_configurations ) || ! is_array( $identity_provider_configurations ) ) {
			$identity_provider_configurations = array();
		}
		foreach ( $identity_provider_configurations as $idp_id => $identity_provider_configuration ) {
			$widget_config = array(
				'widget_config' => array(
					'custom_login_text'    => $identity_provider_configuration['custom_login_text'],
					'custom_greeting_text' => $identity_provider_configuration['custom_greeting_text'],
					'greeting_name'        => $identity_provider_configuration['greeting_name'],
					'custom_logout_text'   => $identity_provider_configuration['custom_logout_text'],
				),
			);
			if ( ! isset( $normalized_model->sso_settings[ $site_url ][ $idp_id ] ) || ! array( $normalized_model->sso_settings[ $site_url ][ $idp_id ] ) ) {
				$normalized_model->sso_settings[ $site_url ][ $idp_id ] = array();
			}
			$normalized_model->sso_settings[ $site_url ][ $idp_id ] = array_merge(
				$normalized_model->sso_settings[ $site_url ][ $idp_id ],
				$widget_config,
			);
		}

		$relay_state_configurations = isset( $plugin_settings['mo_saml_relay_states'] ) ? $plugin_settings['mo_saml_relay_states'] : array();
		if ( ! $plugin_settings ) {
			$relay_state_configurations = maybe_unserialize( get_option( 'mo_saml_relay_states', array() ) );
		}
		if ( empty( $relay_state_configurations ) || ! is_array( $relay_state_configurations ) ) {
			$relay_state_configurations = array();
		}
		foreach ( $relay_state_configurations as $type => $relay_state_configuration ) {
			if ( 'login_relay_state' === $type ) {
				foreach ( $relay_state_configuration as $idp_id => $login_relay_state ) {
					$login_relay_state_config = array(
						'login_relay_state' => $login_relay_state,
					);
					if ( ! isset( $normalized_model->sso_settings[ $site_url ][ $idp_id ] ) || ! array( $normalized_model->sso_settings[ $site_url ][ $idp_id ] ) ) {
						$normalized_model->sso_settings[ $site_url ][ $idp_id ] = array();
					}
					$normalized_model->sso_settings[ $site_url ][ $idp_id ] = array_merge(
						$normalized_model->sso_settings[ $site_url ][ $idp_id ],
						$login_relay_state_config,
					);
				}
			} elseif ( 'logout_relay_state' === $type ) {
				foreach ( $relay_state_configuration as $idp_id => $logout_relay_state ) {
					$logout_relay_state_config = array(
						'logout_relay_state' => $logout_relay_state,
					);
					if ( ! isset( $normalized_model->sso_settings[ $site_url ][ $idp_id ] ) || ! array( $normalized_model->sso_settings[ $site_url ][ $idp_id ] ) ) {
						$normalized_model->sso_settings[ $site_url ][ $idp_id ] = array();
					}
					$normalized_model->sso_settings[ $site_url ][ $idp_id ] = array_merge(
						$normalized_model->sso_settings[ $site_url ][ $idp_id ],
						$logout_relay_state_config,
					);
				}
			}
		}

		$complete_logout_settings = isset( $plugin_settings['saml_force_complete_logout'] ) ? $plugin_settings['saml_force_complete_logout'] : array();
		if ( ! $plugin_settings ) {
			$complete_logout_settings = maybe_unserialize( get_option( 'saml_force_complete_logout', array() ) );
		}
		if ( empty( $complete_logout_settings ) || ! is_array( $complete_logout_settings ) ) {
			$complete_logout_settings = array();
		}
		foreach ( $complete_logout_settings as $idp => $configured ) {
			$complete_logout_config = array(
				'saml_force_complete_logout' => $configured,
			);
			if ( ! isset( $normalized_model->sso_settings[ $site_url ][ $idp_id ] ) || ! array( $normalized_model->sso_settings[ $site_url ][ $idp_id ] ) ) {
				$normalized_model->sso_settings[ $site_url ][ $idp_id ] = array();
			}
			$normalized_model->sso_settings[ $site_url ][ $idp_id ] = array_merge(
				$normalized_model->sso_settings[ $site_url ][ $idp_id ],
				$complete_logout_config,
			);
		}
	}

	/**
	 * Map the default IDP SSO settings.
	 *
	 * @param Normalized_Migration_Model $normalized_model The normalized model.
	 * @param array                      $plugin_settings The plugin settings.
	 * @param string                     $site_url The site URL.
	 * @return void
	 */
	private function map_default_idp_sso_settings( $normalized_model, $plugin_settings, $site_url ) {
		if ( $plugin_settings ) {
			$site_auto_redirection_option = isset( $plugin_settings['mo_saml_redirect_default_idp'] ) && $plugin_settings['mo_saml_redirect_default_idp'] ? 'default_idp' : ( isset( $plugin_settings['mo_saml_registered_only_access'] ) && $plugin_settings['mo_saml_registered_only_access'] ? 'wp_login' : ( isset( $plugin_settings['mo_saml_auto_redirect_to_public_page'] ) && $plugin_settings['mo_saml_auto_redirect_to_public_page'] ? 'public_page' : 'default_idp' ) );
		} else {
			$site_auto_redirection_option = get_option( 'mo_saml_redirect_default_idp' ) ? 'default_idp' : ( get_option( 'mo_saml_registered_only_access' ) ? 'wp_login' : ( get_option( 'mo_saml_auto_redirect_to_public_page' ) ? 'public_page' : 'default_idp' ) );
		}
		$default_idp_sso_settings = empty( $normalized_model->sso_settings[ $site_url ]['DEFAULT'] ) ? array() : $normalized_model->sso_settings[ $site_url ]['DEFAULT'];
		$normalized_model->sso_settings[ $site_url ]['DEFAULT'] = array_merge(
				array(
				'enable_site_auto_redirect'     => isset( $plugin_settings['mo_saml_enable_auto_redirect'] ) ? $plugin_settings['mo_saml_enable_auto_redirect'] : get_option( 'mo_saml_enable_auto_redirect', '' ),
				'site_auto_redirection_option'  => $site_auto_redirection_option,
				'public_page_url'               => ! empty( $plugin_settings['mo_saml_idp_list_url'] ) ? $plugin_settings['mo_saml_idp_list_url'] : get_option( 'mo_saml_idp_list_url', $site_url ),
				'enable_rss_feed_access'        => isset( $plugin_settings['mo_saml_enable_rss_access'] ) ? Migration_Helper::map_value( 'true_to_checked', $plugin_settings['mo_saml_enable_rss_access'] ) : Migration_Helper::map_value( 'true_to_checked', get_option( 'mo_saml_enable_rss_access', '' ) ),
				'enable_force_authentication'   => isset( $plugin_settings['mo_saml_force_authentication'] ) ? Migration_Helper::map_value( 'true_to_checked', $plugin_settings['mo_saml_force_authentication'] ) : Migration_Helper::map_value( 'true_to_checked', get_option( 'mo_saml_force_authentication', '' ) ),
				'redirect_from_wp_login'        => isset( $plugin_settings['mo_saml_enable_login_redirect'] ) ? Migration_Helper::map_value( 'true_to_checked', $plugin_settings['mo_saml_enable_login_redirect'] ) : Migration_Helper::map_value( 'true_to_checked', get_option( 'mo_saml_enable_login_redirect', '' ) ),
				'enable_backdoor_url_login'     => isset( $plugin_settings['mo_saml_allow_wp_signin'] ) ? Migration_Helper::map_value( 'true_to_checked', $plugin_settings['mo_saml_allow_wp_signin'] ) : Migration_Helper::map_value( 'true_to_checked', get_option( 'mo_saml_allow_wp_signin', '' ) ),
				'backdoor_url'                  => ! empty( $plugin_settings['mo_saml_backdoor_url'] ) ? $plugin_settings['mo_saml_backdoor_url'] : get_option( 'mo_saml_backdoor_url', 'false' ),
				'enable_domain_mapping'         => isset( $plugin_settings['mo_saml_enable_domain_mapping'] ) ? Migration_Helper::map_value( 'true_to_checked', $plugin_settings['mo_saml_enable_domain_mapping'] ) : Migration_Helper::map_value( 'true_to_checked', get_option( 'mo_saml_enable_domain_mapping', '' ) ),
				'domain_mapping_config'         => isset( $plugin_settings['saml_idp_domain_mapping'] ) ? $plugin_settings['saml_idp_domain_mapping'] : maybe_unserialize( get_option( 'saml_idp_domain_mapping', array() ) ),
				'domain_mapping_fail_option'    => ! empty( $plugin_settings )
					? ( ! empty( $plugin_settings['mo_saml_fallback_to_default'] ?? false ) ? 'default_idp' : 'wp_login' )
					: ( get_option( 'mo_saml_fallback_to_default' ) ? 'default_idp' : 'wp_login' ),
				'sso_show_user'                 => isset( $plugin_settings['mo_saml_sso_show_user'] ) ? Migration_Helper::map_value( 'on_to_checked', $plugin_settings['mo_saml_sso_show_user'] ) : Migration_Helper::map_value( 'on_to_checked', get_option( 'mo_saml_sso_show_user', '' ) ),
				'account_creation_disabled_msg' => isset( $plugin_settings['mo_saml_account_creation_disabled_msg'] ) ? $plugin_settings['mo_saml_account_creation_disabled_msg'] : get_option( 'mo_saml_account_creation_disabled_msg', '' ),
				'restricted_domain_error_msg'   => isset( $plugin_settings['mo_saml_restricted_domain_error_msg'] ) ? $plugin_settings['mo_saml_restricted_domain_error_msg'] : get_option( 'mo_saml_restricted_domain_error_msg', '' ),
				'hide_wp_login'                 => isset( $plugin_settings['mo_saml_enable_hide_wp_login'] ) ? Migration_Helper::map_value( 'true_to_checked', $plugin_settings['mo_saml_enable_hide_wp_login'] ) : Migration_Helper::map_value( 'true_to_checked', get_option( 'mo_saml_enable_hide_wp_login', '' ) ),
				'allow_wp_signin'               => isset( $plugin_settings['mo_saml_allow_wp_signin'] ) ? Migration_Helper::map_value( 'true_to_checked', $plugin_settings['mo_saml_allow_wp_signin'] ) : Migration_Helper::map_value( 'true_to_checked', get_option( 'mo_saml_allow_wp_signin', '' ) )
			),
			$default_idp_sso_settings
		);
	}
}
