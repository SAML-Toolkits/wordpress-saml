<?php
/**
 * SP Setup Handler
 *
 * Handles IDP Configuration operations.
 *
 * @package miniorange-saml-20-single-sign-on/module/base/handler/admin
 */

namespace MOSAML\Module\Base\Handler\Admin;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\SRC\Interfaces\Form_Data_Handler_Interface;
use MOSAML\SRC\Classes\Metadata_Reader;
use MOSAML\SRC\Utils\DB_Utils;
use MOSAML\SRC\Utils\Utility;
use MOSAML\SRC\Utils\Certificate_Utility;
use MOSAML\SRC\Utils\Error_Success_Message;
use MOSAML\SRC\Constant\Constants;
use MOSAML\SRC\Constant\Error_Codes_Enums;
use MOSAML\SRC\Utils\Feature_Control;

use Exception;

/**
 * SP Setup Handler.
 */
class SP_Setup_Data_Handler implements Form_Data_Handler_Interface {

	/**
	 * ID (Primary key).
	 *
	 * @var int
	 */
	public $id;

	/**
	 * Environment ID.
	 *
	 * @var string
	 */
	public $environment_id;

	/**
	 * IDP ID.
	 *
	 * @var string
	 */
	public $idp_id;

	/**
	 * IDP name.
	 *
	 * @var string
	 */
	public $idp_name;

	/**
	 * IDP Entity ID.
	 *
	 * @var string
	 */
	public $entity_id;

	/**
	 * IDP SSO URL.
	 *
	 * @var string
	 */
	public $sso_url;

	/**
	 * IDP SLO URL.
	 *
	 * @var string
	 */
	public $slo_url;

	/**
	 * IDP cert.
	 *
	 * @var array|string
	 */
	public $idp_certificate;

	/**
	 * IDP SLO Response URL.
	 *
	 * @var string
	 */
	public $slo_response_url;

	/**
	 * Password reset URL.
	 *
	 * @var string
	 */
	public $password_reset_url;

	/**
	 * Character encoding.
	 *
	 * @var string
	 */
	public $character_encoding = 'checked';

	/**
	 * Assertion time validity.
	 *
	 * @var string
	 */
	public $assertion_time_validity = 'checked';

	/**
	 * Sign SSO/SLO request.
	 *
	 * @var bool|string
	 */
	public $sign_sso_slo_request;

	/**
	 * SSO binding.
	 *
	 * @var string
	 */
	public $sso_binding;

	/**
	 * SLO binding.
	 *
	 * @var string
	 */
	public $slo_binding;

	/**
	 * SP Entity ID.
	 *
	 * @var string
	 */
	public $sp_entity_id;

	/**
	 * Sync metadata.
	 *
	 * @var bool
	 */
	public $sync_metadata;

	/**
	 * Metadata URL.
	 *
	 * @var string
	 */
	public $metadata_url;

	/**
	 * Sync interval time.
	 *
	 * @var string
	 */
	public $sync_time_interval;

	/**
	 * Sync only certificate.
	 *
	 * @var bool
	 */
	public $sync_only_certificate = 'checked';

	/**
	 * Name ID format.
	 *
	 * @var string
	 */
	public $name_id_format;

	/**
	 * Status.
	 *
	 * @var string
	 */
	public $status;

	/**
	 * Default IDP.
	 *
	 * @var bool
	 */
	public $default_idp;

	/**
	 * SP certificate.
	 *
	 * @var string
	 */
	public $sp_certificate;

	/**
	 * SP private key.
	 *
	 * @var string
	 */
	public $sp_private_key;

	/**
	 * Test configuration attributes.
	 *
	 * @var string|array
	 */
	public $test_config_attributes;

	/**
	 * SAML request.
	 *
	 * @var string
	 */
	public $saml_request;

	/**
	 * SAML response.
	 *
	 * @var string
	 */
	public $saml_response;

	/**
	 * Constructor to set defaults.
	 */
	public function __construct() {
		$this->environment_id          = DB_Utils::get_environment_details( 'id', false );
		$this->sp_entity_id            = DB_Utils::get_sp_details( 'sp_entity_id', false );
		$this->character_encoding      = 'checked';
		$this->assertion_time_validity = 'checked';
	}

	/**
	 * Get the table name.
	 *
	 * @return string
	 */
	public function get_table_name() {
		return Constants::DATABASE_TABLE_NAMES['idp_details'];
	}

	/**
	 * Validate and save the data.
	 *
	 * @return void
	 */
	public function validate_and_save_data() {
		$upload_metadata = Utility::sanitize_post_data( 'upload_metadata' );

		if ( 'url' === $upload_metadata || 'file' === $upload_metadata ) {
			if ( ! $this->handle_upload_metadata( array() ) ) {
				return;
			}
		} elseif ( 'manual' === $upload_metadata ) {
			$this->handle_manual_configuration( array() );
			if ( false === $this->idp_certificate || empty( $this->sso_url ) || empty( $this->entity_id ) ) {
				return;
			}
		}

		$idp_name = is_string( $this->idp_name ) ? trim( $this->idp_name ) : '';
		if ( empty( $idp_name ) ) {
			Error_Success_Message::show_admin_notice( 'Identity Provider Name is required. Please enter a valid Identity Provider name.', 'ERROR' );
			return;
		}

		$existing_idp = DB_Utils::get_records( $this->get_table_name(), array( 'environment_id' => $this->environment_id ) );
		$is_editing   = false;
		if ( $existing_idp ) {
			foreach ( $existing_idp as $idp ) {
				if ( $idp->idp_id === $this->idp_id ) {
					$this->id                     = $idp->id;
					$is_editing                   = true;
					$this->default_idp            = ! empty( $idp->default_idp );
					$this->test_config_attributes = isset( $idp->test_config_attributes ) ? maybe_unserialize( $idp->test_config_attributes ) : null;
					break;
				}

				if ( 'All IDPs' !== $idp->idp_name && Feature_Control::is_feature_locked( 4 ) ) {
					$redirect_url = add_query_arg(
						array(
							'page' => 'mo_saml_settings',
							'tab'  => 'sp_setup',
						),
						admin_url( 'admin.php' )
					);
					wp_safe_redirect( $redirect_url );
					exit();
				}
			}
		}

		if ( ! $is_editing ) {
			$selected_environment_id = DB_Utils::get_environment_details( 'id', false );
			$this->default_idp       = empty( Utility::get_default_idp( $selected_environment_id ) );
		}

		$sp_setup_data_variables = get_object_vars( $this );
		if ( ! $is_editing && ( ! isset( $sp_setup_data_variables['default_idp'] ) || '' === $sp_setup_data_variables['default_idp'] ) ) {
			unset( $sp_setup_data_variables['default_idp'] );
		}

		$sp_setup_data_variables = array_diff_key(
			$sp_setup_data_variables,
			array_flip( array( 'sync_metadata', 'metadata_url', 'sync_time_interval', 'sync_only_certificate' ) )
		);
		if ( null === $this->idp_id ) {
			return;
		}

		if ( ! empty( $this->idp_name ) && ! preg_match( '#^(?=.*[a-zA-Z0-9])[a-zA-Z0-9\s_\-@]+$#', $this->idp_name ) ) {
			Error_Success_Message::show_admin_notice( 'Please match the requested format for Identity Provider Name. Special characters are not allowed except underscore(_), hyphen(-) and @.', 'ERROR' );
			return;
		}

		$duplicate_idp_name = DB_Utils::get_records(
			$this->get_table_name(),
			array(
				'idp_name'       => $this->idp_name,
				'environment_id' => $this->environment_id,
			),
			true
		);
		if ( ( empty( $this->entity_id ) || empty( $this->sso_url ) || empty( $this->idp_certificate ) ) && 'manual' !== $upload_metadata ) {
			$missing_fields   = array();
			$missing_fields[] = empty( $this->entity_id ) ? 'EntityID' : '';
			$missing_fields[] = empty( $this->sso_url ) ? 'Login URL' : '';
			$missing_fields[] = empty( $this->idp_certificate ) ? 'Signing Certificate' : '';

			if ( ! empty( $missing_fields ) ) {
				$error_message = 'The Identity Provider\'s metadata is missing the following required fields. Please check your IdP configuration.';
				foreach ( $missing_fields as $field ) {
					if ( ! empty( $field ) ) {
						$error_message .= '<li>' . $field . '</li>';
					}
				}
				Error_Success_Message::show_admin_notice( $error_message, 'ERROR' );
			}
			return;
		}

		if ( $duplicate_idp_name && $this->idp_id !== $duplicate_idp_name->idp_id ) {
			Error_Success_Message::show_admin_notice( 'Identity Provider with name <em>' . esc_html( $this->idp_name ) . '</em> already exists. Try another Identity Provider name.', 'ERROR' );
			return;
		}

		DB_Utils::insert_or_update(
			$this->get_table_name(),
			$sp_setup_data_variables,
			array(
				'idp_id'         => $this->idp_id,
				'environment_id' => $this->environment_id,
			)
		);
		if ( 'manual' === $upload_metadata ) {
			Error_Success_Message::show_admin_notice( 'Identity Provider details saved successfully.', 'SUCCESS' );
		} else {
			Error_Success_Message::show_admin_notice( 'Identity Provider details retrieved successfully', 'SUCCESS' );
			$redirect_url  = add_query_arg(
				array(
					'page'   => 'mo_saml_settings',
					'tab'    => 'sp_setup',
					'action' => 'edit',
					'idp'    => $this->idp_id,
				),
				admin_url( 'admin.php' )
			);
			$redirect_url .= '#mosaml_test_configuration_button_div';
			wp_safe_redirect( $redirect_url );
		}
	}

	/**
	 * Handle upload metadata (URL or file).
	 *
	 * @param array $details Additional details for configuration.
	 * @return bool True if metadata was processed successfully, false otherwise.
	 */
	protected function handle_upload_metadata( $details ) {
		$mode   = Utility::sanitize_post_data( 'upload_metadata' );
		$idp_id = Utility::sanitize_post_data( 'idp_id' );
		$idp    = Utility::sanitize_get_data( 'idp' );
		if ( ! empty( $idp_id ) || ! empty( $idp ) ) {
			$this->idp_id = ! empty( $idp_id ) ? $idp_id : $idp;
		}

		$content = ( 'url' === $mode ) ? $this->get_metadata_from_url() : $this->get_metadata_from_file();
		if ( ! $content ) {
			return false;
		}
		$metadata_reader    = new Metadata_Reader();
		$entity_descriptors = $metadata_reader->get_entity_descriptors( $content );
		if ( empty( $entity_descriptors ) ) {
			Error_Success_Message::display_error_notice_to_admin( Error_Codes_Enums::$error_codes['WPSAMLERR026'] );
			return false;
		}
		try {
			$metadata_reader->read_metadata( $this, $entity_descriptors[0], $details );
		} catch ( Exception $e ) {
			Error_Success_Message::display_error_notice_to_admin( Error_Codes_Enums::$error_codes['WPSAMLERR026'] );
			return false;
		}
		if ( empty( $this->idp_name ) || null === $this->idp_name ) {
			$this->idp_name = Utility::sanitize_post_data( 'saml_identity_metadata_provider' );
		}
		if ( empty( $this->environment_id ) ) {
			$this->environment_id = DB_Utils::get_environment_details( 'id', false );
		}
		if ( empty( $this->idp_id ) ) {
			$this->idp_id = Utility::generate_idp_id();
		}
		return true;
	}

	/**
	 * Handle manual configuration.
	 *
	 * @param array $details Additional details for configuration.
	 * @return void
	 */
	protected function handle_manual_configuration( $details ) {
		$get_url = function ( $key ) {
			$url = Utility::sanitize_post_data( $key );
			return ! empty( $url ) ? esc_url_raw( $url ) : '';
		};

		$get_certificate = function ( $key ) {
			$certs = Utility::sanitize_post_data( $key );
			foreach ( $certs as $cert_index => $cert ) {
				unset( $cert_index );
				$cert = Certificate_Utility::sanitize_certificate( $cert );
				if ( empty( $cert ) ) {
					return false;
				}

				// phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_set_error_handler -- Needed to prevent OpenSSL warnings.
				set_error_handler(
					static function ( $errno, $errstr ) {
						unset( $errno, $errstr );
						return true;
					}
				);
				$x509 = openssl_x509_read( $cert );
				restore_error_handler();

				if ( false === $x509 ) {
					return false;
				}
			}
			return Certificate_Utility::format_certificate( $certs );
		};

		$this->environment_id = DB_Utils::get_environment_details( 'id', false );
		$this->idp_id         = ! empty( Utility::sanitize_post_data( 'idp_id' ) ) ? Utility::sanitize_post_data( 'idp_id' ) : ( ! empty( Utility::sanitize_get_data( 'idp' ) ) ? Utility::sanitize_get_data( 'idp' ) : Utility::generate_idp_id() );
		$this->idp_name       = Utility::sanitize_post_data( 'saml_identity_name' );
		$this->entity_id      = Utility::sanitize_post_data( 'saml_issuer' );
		$this->sso_url        = $get_url( 'saml_login_url' );
		if ( empty( $this->sso_url ) || empty( $this->entity_id ) ) {
			Error_Success_Message::show_admin_notice( 'All the fields are required. Please enter valid entries.', 'ERROR' );
			return;
		}
		$this->idp_certificate = $get_certificate( 'saml_x509_certificate' );
		if ( empty( $this->idp_certificate ) ) {
			Error_Success_Message::show_admin_notice( 'Invalid certificate: Please enter a valid certificate.', 'ERROR' );
			return;
		}
		$this->character_encoding      = Utility::sanitize_post_data( 'enable_iconv' );
		$this->assertion_time_validity = Utility::sanitize_post_data( 'mo_saml_assertion_time_validity' );
		$this->sso_binding             = Utility::sanitize_post_data( 'saml_login_binding_type' );
		$this->sp_entity_id            = ! empty( Utility::sanitize_post_data( 'saml_sp_entity_id' ) ) ? Utility::sanitize_post_data( 'saml_sp_entity_id' ) : DB_Utils::get_sp_details( 'sp_entity_id', false );
		$this->name_id_format          = Utility::sanitize_post_data( 'saml_nameid_format' );
		$this->status                  = Utility::sanitize_post_data( 'status' ) ? Utility::sanitize_post_data( 'status' ) : 'active';
	}

	/**
	 * Get the data.
	 *
	 * @param array $where The where clause.
	 * @param bool  $single_record Whether to return a single record or an array of records.
	 * @return array|object The data.
	 */
	public function get_data( $where = array(), $single_record = true ) {
		if ( Utility::is_legacy_data_fallback_required() ) {
			$self_object = apply_filters( 'mosaml_legacy_data_fallback_object', $this, $where );
			return $single_record ? $self_object : array( $self_object );
		}
		$db_values = DB_Utils::get_records( $this->get_table_name(), $where );
		$result    = array();
		if ( empty( $db_values ) || null === $db_values ) {
			return $single_record ? $this : array();
		}
		$class_object = new self();
		foreach ( $db_values as $db_value ) {
			$new_data = new $class_object();
			foreach ( get_object_vars( $this ) as $key => $value ) {
				if ( property_exists( $db_value, $key ) && null !== $db_value->$key ) {
					if ( ( 'idp_certificate' === $key || 'test_config_attributes' === $key ) && ! empty( $db_value->$key ) ) {
						$new_data->$key = maybe_unserialize( $db_value->$key );
					} else {
						$new_data->$key = $db_value->$key;
					}
				}
			}
			if ( $single_record ) {
				return $new_data;
			}
			$result[] = $new_data;
		}
		return $result;
	}

	/**
	 * Handle IDP list actions.
	 *
	 * @param string       $action  The action to handle.
	 * @param array|string $records The records to handle.
	 * @return void
	 */
	public function handle_idp_list_actions( $action, $records ) {
		$records           = (array) $records;
		$environment_id    = DB_Utils::get_environment_details( 'id', false );
		$more_than_one_idp = count( $records ) > 1 ? 's' : '';

		switch ( $action ) {
			case 'delete':
				foreach ( $records as $record ) {
					wp_unschedule_event( wp_next_scheduled( Constants::METADATA_SYNC_CRON_HOOK, array( $record ) ), Constants::METADATA_SYNC_CRON_HOOK, array( $record ) );
					DB_Utils::delete_records(
						Constants::DATABASE_TABLE_NAMES['idp_details'],
						array(
							'idp_id'         => $record,
							'environment_id' => $environment_id,
						)
					);
				}
				$selected_default_idp = Utility::sanitize_post_data( 'bulk_action_default_idp_id' );
				if ( ! empty( $selected_default_idp ) ) {
					DB_Utils::insert_or_update(
						Constants::DATABASE_TABLE_NAMES['idp_details'],
						array(
							'default_idp' => true,
							'status'      => 'active',
						),
						array(
							'idp_id'         => $selected_default_idp,
							'environment_id' => $environment_id,
						)
					);
				}
				Error_Success_Message::show_admin_notice( '<em>IDP</em>' . $more_than_one_idp . ' deleted successfully', 'SUCCESS' );
				break;

			case 'default_idp':
				DB_Utils::insert_or_update(
					Constants::DATABASE_TABLE_NAMES['idp_details'],
					array( 'default_idp' => false ),
					array(
						'environment_id' => $environment_id,
					)
				);
				foreach ( $records as $record ) {
					DB_Utils::insert_or_update(
						Constants::DATABASE_TABLE_NAMES['idp_details'],
						array( 'default_idp' => true ),
						array(
							'idp_id'         => $record,
							'environment_id' => $environment_id,
						)
					);
				}
				Error_Success_Message::show_admin_notice( 'Default IDP updated successully.', 'SUCCESS' );
				break;

			default:
				if ( 'active' === $action && Utility::mo_saml_is_idp_license_limit_exceeded( $environment_id ) ) {
					Error_Success_Message::show_admin_notice(
						'You have configured more Identity Providers than your license allows. Remove extra IDP configurations or review your license before activating.'
					);
					break;
				}
				$selected_default_idp = Utility::sanitize_post_data( 'bulk_action_default_idp_id' );
				foreach ( $records as $record ) {
					$data = array(
						'idp_id'         => $record,
						'environment_id' => $environment_id,
						'status'         => $action,
					);

					if ( ! empty( $selected_default_idp ) ) {
						$data['default_idp'] = false;
					}

					DB_Utils::insert_or_update(
						Constants::DATABASE_TABLE_NAMES['idp_details'],
						$data,
						array(
							'idp_id'         => $record,
							'environment_id' => $environment_id,
						)
					);
				}
				if ( ! empty( $selected_default_idp ) ) {
					DB_Utils::insert_or_update(
						Constants::DATABASE_TABLE_NAMES['idp_details'],
						array(
							'default_idp' => true,
							'status'      => 'active',
						),
						array(
							'idp_id'         => $selected_default_idp,
							'environment_id' => $environment_id,
						)
					);
				}
				$action_text = 'inactive' === $action ? 'deactivated' : 'activated';
				Error_Success_Message::show_admin_notice( 'IDP' . $more_than_one_idp . ' ' . $action_text . ' successfully', 'SUCCESS' );
				break;
		}
	}

	/**
	 * Get metadata content from URL.
	 *
	 * @return string|false Metadata content or false on failure.
	 */
	protected function get_metadata_from_url() {
		$metadata_url     = Utility::sanitize_post_data( 'metadata_url' );
		$metadata_content = Utility::get_content_from_url( $metadata_url );
		if ( ! $metadata_content ) {
			Error_Success_Message::show_admin_notice( 'Please provide a valid metadata URL.' );
			return false;
		}
		return $metadata_content;
	}

	/**
	 * Get metadata content from file.
	 *
	 * @return string|false Metadata content or false on failure.
	 */
	protected function get_metadata_from_file() {
		$metadata_file    = Utility::get_global_file_data( 'metadata_file' );
		$metadata_content = Utility::get_content_from_file( $metadata_file );
		if ( ! $metadata_content ) {
			Error_Success_Message::show_admin_notice( 'Please provide a valid metadata file.' );
			return false;
		}
		return $metadata_content;
	}

	/**
	 * Clear test configuration attributes.
	 *
	 * @return void
	 */
	public function clear_test_config_attributes() {
		$idp_name       = Utility::sanitize_post_data( 'idp_name' );
		$environment_id = DB_Utils::get_environment_details( 'id', false );
		if ( empty( $idp_name ) ) {
			return;
		}
		DB_Utils::insert_or_update(
			$this->get_table_name(),
			array( 'test_config_attributes' => null ),
			array(
				'id'             => $idp_name,
				'environment_id' => $environment_id,
			)
		);
		Error_Success_Message::show_admin_notice( 'Attributes list removed successfully', 'SUCCESS' );
	}

	/**
	 * Save the data.
	 *
	 * @param object $config_obj The config object.
	 * @param array  $details The details array.
	 * @return void
	 */
	public function save_data( $config_obj, $details = array() ) {
		$this->environment_id = ! empty( $details['environment_url'] ) ? DB_Utils::get_records( Constants::DATABASE_TABLE_NAMES['environments'], array( 'environment_url' => $details['environment_url'] ), true )->id : DB_Utils::get_environment_details( 'id', false );
		if ( ! empty( $details['idp_id'] ) ) {
			$idp_id = 'DEFAULT' === $details['idp_id'] ? DB_Utils::get_records(
				Constants::DATABASE_TABLE_NAMES['idp_details'],
				array(
					'environment_id' => $this->environment_id,
					'idp_name'       => 'ALL IDPs',
				),
				true
			)->idp_id : $details['idp_id'];
		}
		$this->idp_id            = ! empty( $this->idp_id ) ? $this->idp_id : $idp_id;
		$sp_setup_data_variables = get_object_vars( $this );

		DB_Utils::insert_or_update(
			$this->get_table_name(),
			$sp_setup_data_variables,
			array(
				'idp_id'         => $this->idp_id,
				'environment_id' => $this->environment_id,
			)
		);
	}
}
