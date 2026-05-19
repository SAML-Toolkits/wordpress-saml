<?php
/**
 * Metadata Sync Data Handler for Premium version.
 * This is the base implementation - metadata sync is a Premium+ feature.
 *
 * @package miniorange-saml-20-single-sign-on/module/premium/handler/admin
 */

namespace MOSAML\Module\Premium\Handler\Admin;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\Module\Standard\Handler\Admin\Metadata_Sync_Data_Handler as Standard_Metadata_Sync_Data_Handler;
use MOSAML\SRC\Interfaces\Form_Data_Handler_Interface;
use MOSAML\SRC\Utils\Utility;
use MOSAML\SRC\Utils\DB_Utils;
use MOSAML\SRC\Utils\Error_Success_Message;
use MOSAML\SRC\Classes\Metadata_Reader;
use MOSAML\SRC\Exception\Metadata_Upload_Exception;
use MOSAML\SRC\Exception\Metadata_Parse_Exception;
use MOSAML\SRC\Exception\Metadata_Processing_Exception;
use MOSAML\SRC\Constant\Constants;
use Exception;

/**
 * Premium Metadata Sync Data Handler.
 * Core implementation for metadata sync functionality (Premium+ feature).
 */
class Metadata_Sync_Data_Handler extends Standard_Metadata_Sync_Data_Handler implements Form_Data_Handler_Interface {

	/**
	 * Get table name.
	 *
	 * @return string
	 */
	public function get_table_name() {
		return Constants::DATABASE_TABLE_NAMES['idp_details'];
	}

	/**
	 * Validate and save metadata sync data.
	 *
	 * @return void
	 * @throws Exception When version check fails or database operations fail.
	 */
	public function validate_and_save_data() {
		try {
			$this->environment_id        = DB_Utils::get_environment_details( 'id', false );
			$this->idp_id                = Utility::sanitize_post_data( 'idp_id' );
			$this->sync_metadata         = Utility::sanitize_post_data( 'sync_metadata' );
			$this->metadata_url          = Utility::sanitize_post_data( 'metadata_url' );
			$this->sync_only_certificate = Utility::sanitize_post_data( 'sync_certificate_metadata' );
			$this->sync_time_interval    = Utility::sanitize_post_data( 'sync_time_interval' ) ?: 'daily';

			if ( 'checked' === $this->sync_metadata ) {
				$allowed_intervals = array_keys( Utility::get_sync_interval_options() );
				if ( empty( $this->sync_time_interval ) || ! in_array( $this->sync_time_interval, $allowed_intervals, true ) ) {
					Error_Success_Message::show_admin_notice( 'Please select a valid sync interval before enabling metadata sync.' );
					return;
				}
				if ( empty( $this->metadata_url ) ) {
					Error_Success_Message::show_admin_notice( 'Please provide a valid metadata URL to enable metadata sync.' );
					return;
				}
				Utility::enable_metadata_sync( $this );
				$this->sync_metadata_from_url( $this->idp_id, $this->metadata_url, $this->sync_only_certificate );
				Error_Success_Message::show_admin_notice( 'Metadata sync enabled and synced successfully.', 'SUCCESS' );
			} else {
				Utility::disable_metadata_sync( $this );
				Error_Success_Message::show_admin_notice( 'Metadata sync has been disabled successfully.', 'SUCCESS' );
			}

			$sync_data_variables = get_object_vars( $this );
			if ( isset( $sync_data_variables['id'] ) ) {
				unset( $sync_data_variables['id'] );
			}

			try {
				DB_Utils::insert_or_update(
					$this->get_table_name(),
					$sync_data_variables,
					array(
						'idp_id'         => $this->idp_id,
						'environment_id' => $this->environment_id,
					)
				);
			} catch ( Exception $db_e ) {
				Error_Success_Message::show_admin_notice( 'Database error during metadata sync save: ' . esc_html( $db_e->getMessage() ) );
				throw $db_e;
			}

			Error_Success_Message::show_admin_notice( 'Metadata sync settings saved successfully.', 'SUCCESS' );

		} catch ( Exception $e ) {
			Error_Success_Message::show_admin_notice( 'Metadata sync feature encountered an error: ' . esc_html( $e->getMessage() ) );
		}
	}

	/**
	 * Get the metadata sync data.
	 *
	 * @param array $where The where clause.
	 * @param bool  $single_record Whether to return a single object or array.
	 * @return object|array The retrieved data.
	 */
	public function get_data( $where = array(), $single_record = true ) {
		$db_values = DB_Utils::get_records( $this->get_table_name(), $where );

		if ( empty( $db_values ) || null === $db_values ) {
			return $single_record ? $this : array();
		}

		$result       = array();
		$class_object = new self();
		foreach ( $db_values as $db_value ) {
			$new_data = new $class_object();
			foreach ( get_object_vars( $new_data ) as $key => $value ) {
				if ( property_exists( $db_value, $key ) && null !== $db_value->$key ) {
					$new_data->$key = $db_value->$key;
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
	 * Sync metadata from URL for a specific IDP.
	 *
	 * @param string $idp_id The IDP ID.
	 * @param string $metadata_url The metadata URL.
	 * @param bool   $sync_only_certificate Whether to sync only certificates.
	 * @return void
	 * @throws Metadata_Upload_Exception If sync fails.
	 */
	private function sync_metadata_from_url( $idp_id, $metadata_url, $sync_only_certificate = false ) {
		$response = Utility::wp_remote_call( $metadata_url, array( 'sslverify' => false ) );

		if ( is_wp_error( $response ) ) {
			throw new Metadata_Upload_Exception( 'Failed to fetch metadata: ' . esc_html( $response->get_error_message() ) );
		}

		$content = wp_remote_retrieve_body( $response );

		if ( empty( $content ) ) {
			throw new Metadata_Upload_Exception( 'Empty metadata content received from URL' );
		}

		$this->process_metadata_content( $content, $idp_id, $sync_only_certificate );
	}

	/**
	 * Process metadata content and update IDP configuration.
	 * Supports certificate-only sync when $sync_only_certificate is true.
	 *
	 * @param string $content The metadata XML content.
	 * @param string $idp_id The IDP ID.
	 * @param bool   $sync_only_certificate Whether to sync only certificates from metadata.
	 * @return void
	 * @throws Metadata_Parse_Exception If XML parsing fails.
	 * @throws Metadata_Processing_Exception If processing fails.
	 */
	private function process_metadata_content( $content, $idp_id, $sync_only_certificate ) {
		try {
			$dom = Utility::safe_load_xml( $content, 'METADATA_SYNC_PROCESSING', true );
			if ( ! $dom ) {
				throw new Metadata_Parse_Exception( 'Failed to parse metadata XML' );
			}

			$current_data = DB_Utils::get_records( Constants::DATABASE_TABLE_NAMES['idp_details'], array( 'idp_id' => $idp_id ), true );
			if ( ! $current_data ) {
				throw new Metadata_Processing_Exception( 'IDP not found: ' . esc_html( $idp_id ) );
			}

			$metadata_reader    = new Metadata_Reader();
			$entity_descriptors = $metadata_reader->get_entity_descriptors( $content );

			if ( empty( $entity_descriptors ) ) {
				throw new Metadata_Processing_Exception( 'No EntityDescriptor found in metadata' );
			}

			$updated_dto = $metadata_reader->read_metadata(
				$current_data,
				$entity_descriptors[0],
				array(
					'sync_only_certificate' => $sync_only_certificate,
					'slo_service'           => true,
					'sign_request'          => true,
				)
			);

			$update_data = get_object_vars( $updated_dto );
			unset( $update_data['id'] );
			if ( empty( $update_data['idp_id'] ) ) {
				$update_data['idp_id'] = $idp_id;
			}
			if ( isset( $current_data->environment_id ) && empty( $update_data['environment_id'] ) ) {
				$update_data['environment_id'] = $current_data->environment_id;
			}

			$where = array( 'idp_id' => $idp_id );
			if ( isset( $current_data->environment_id ) ) {
				$where['environment_id'] = $current_data->environment_id;
			}
			DB_Utils::insert_or_update(
				Constants::DATABASE_TABLE_NAMES['idp_details'],
				$update_data,
				$where
			);

		} catch ( Exception $e ) {
			throw new Metadata_Processing_Exception( 'Metadata processing failed: ' . esc_html( $e->getMessage() ) );
		}
	}

	/**
	 * Static method to handle metadata sync cron job.
	 * This method is called by WordPress cron.
	 *
	 * @param string $idp_id The IDP ID to sync.
	 * @return void
	 */
	public static function handle_metadata_sync_cron( $idp_id ) {
		$idp_data = DB_Utils::get_records( Constants::DATABASE_TABLE_NAMES['idp_details'], array( 'idp_id' => $idp_id ), true );

		if ( ! $idp_data || ! $idp_data->sync_metadata || empty( $idp_data->metadata_url ) ) {
			return;
		}

		$handler = new static();
		$handler->sync_metadata_from_url(
			$idp_id,
			$idp_data->metadata_url,
			$idp_data->sync_only_certificate
		);
	}
}
