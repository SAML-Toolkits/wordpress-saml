<?php
/**
 * SP Setup Handler.
 *
 * @package miniorange-saml-20-single-sign-on/module/enterprise/handler/admin
 */

namespace MOSAML\Module\Enterprise\Handler\Admin;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\Module\Premium\Handler\Admin\SP_Setup_Data_Handler as Premium_SP_Setup_Data_Handler;
use MOSAML\SRC\Interfaces\Form_Data_Handler_Interface;
use MOSAML\SRC\Classes\Metadata_Reader;
use MOSAML\SRC\Utils\Error_Success_Message;
use MOSAML\SRC\Utils\Utility;
use MOSAML\SRC\Utils\DB_Utils;
use MOSAML\SRC\Constant\Constants;

/**
 * SP Setup Handler.
 */
class SP_Setup_Data_Handler extends Premium_SP_Setup_Data_Handler implements Form_Data_Handler_Interface {
	/**
	 * Apply version-specific settings to the data object.
	 * Enterprise version specific settings.
	 *
	 * @return void
	 */
	public function validate_and_save_data() {
		$upload_metadata = Utility::sanitize_post_data( 'upload_metadata' );
		if ( 'url' === $upload_metadata || 'file' === $upload_metadata ) {
			$content = ( 'url' === $upload_metadata ) ? $this->get_metadata_from_url() : $this->get_metadata_from_file();

			if ( ! $content ) {
				return;
			}
			$metadata_reader    = new Metadata_Reader();
			$entity_descriptors = $metadata_reader->get_entity_descriptors( $content );
			if ( empty( $entity_descriptors ) ) {
				return;
			}
			$multiple_entity_descriptors = array_slice( $entity_descriptors, 1 );
			if ( ! empty( $multiple_entity_descriptors ) ) {
				$details = array(
					'multiple_idps' => true,
					'slo_service'   => true,
					'sign_request'  => true,
				);

				foreach ( $multiple_entity_descriptors as $entity_descriptor ) {
					try {
						$idp_details = $metadata_reader->read_metadata( new self(), $entity_descriptor, $details );
						if ( ! empty( $idp_details->idp_id ) ) {
							if ( empty( $idp_details->idp_name ) ) {
								$idp_details->idp_name = $this->generate_idp_name_from_entity_id( $idp_details->entity_id );
							}
							if ( ! empty( $idp_details->idp_name ) && ! preg_match( '#^(?=.*[a-zA-Z0-9])[a-zA-Z0-9\s_\-@]+$#', $idp_details->idp_name ) ) {
								Error_Success_Message::show_admin_notice( 'Please match the requested format for Identity Provider Name. Special characters are not allowed except underscore(_), hyphen(-) and @.', 'ERROR' );
								return;
							}
							$duplicate_idp_name = DB_Utils::get_records(
								$this->get_table_name(),
								array(
									'idp_name'       => $idp_details->idp_name,
									'environment_id' => $idp_details->environment_id,
								),
								true
							);
							if ( $duplicate_idp_name && $idp_details->idp_id !== $duplicate_idp_name->idp_id ) {
								Error_Success_Message::show_admin_notice( 'Identity Provider with name <em>' . esc_html( $idp_details->idp_name ) . '</em> already exists. Try another Identity Provider name.', 'ERROR' );
								return;
							}
							DB_Utils::insert_or_update(
								Constants::DATABASE_TABLE_NAMES['idp_details'],
								get_object_vars( $idp_details ),
								array(
									'environment_id' => $idp_details->environment_id,
									'idp_id'         => $idp_details->idp_id,
								)
							);
						}
					} catch ( \Exception $e ) {
						continue;
					}
				}
			}
		}
		parent::validate_and_save_data();
	}

	/**
	 * Generate IDP name from entity ID.
	 * ENTERPRISE helper method.
	 *
	 * @param string $entity_id Entity ID.
	 * @return string
	 */
	private function generate_idp_name_from_entity_id( $entity_id ) {
		$parsed_url = wp_parse_url( $entity_id );
		if ( isset( $parsed_url['host'] ) ) {
			return str_replace( 'www.', '', $parsed_url['host'] );
		}

		$parts     = explode( '/', rtrim( $entity_id, '/' ) );
		$last_part = end( $parts );
		return ! empty( $last_part ) ? $last_part : 'IDP_' . time();
	}
}
