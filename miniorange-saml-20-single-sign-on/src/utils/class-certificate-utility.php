<?php
/**
 * Certificate Utility class.
 *
 * This class contains utility functions related to the X509 certificate.
 *
 * @package miniorange-saml-20-single-sign-on/utils
 */

namespace MOSAML\SRC\Utils;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\SRC\Constant\Constants;

/**
 * Utility class.
 *
 * This class contains utility functions for the plugin.
 */
class Certificate_Utility {

	/**
	 * Get the expiry date of the certificate.
	 *
	 * @param string|null $certificate The certificate.
	 * @return int The expiry date of the certificate, or 0 if invalid.
	 */
	public static function get_expiry_date_of_certificate( $certificate ) {
		if ( null === $certificate || '' === $certificate ) {
			return 0;
		}
		$parsed_certificate = openssl_x509_parse( $certificate );
		if ( false === $parsed_certificate || ! isset( $parsed_certificate['validTo_time_t'] ) ) {
			return 0;
		}
		return $parsed_certificate['validTo_time_t'];
	}

	/**
	 * Get the remaining days of the certificate.
	 *
	 * @param string|null $certificate The certificate.
	 * @return int The remaining days of the certificate, or 0 if invalid.
	 */
	public static function get_remaining_days_of_certificate( $certificate ) {
		if ( null === $certificate || '' === $certificate ) {
			return 0;
		}
		$parsed_certificate = openssl_x509_parse( $certificate );
		if ( false === $parsed_certificate || ! isset( $parsed_certificate['validTo_time_t'] ) ) {
			return 0;
		}
		$valid_to_time = $parsed_certificate['validTo_time_t'];
		$difference    = $valid_to_time - time();
		return (int) round( $difference / ( 60 * 60 * 24 ) );
	}

	/**
	 * Format certificate data for consistent storage.
	 *
	 * This function ensures certificate input gets the same formatting
	 * as certificates extracted from metadata, fixing formatting inconsistencies.
	 *
	 * @param array|string $certificates Certificate array from form or single certificate.
	 * @return string Serialized array of formatted certificates.
	 */
	public static function format_certificate( $certificates ) {
		if ( empty( $certificates ) ) {
			return '';
		}

		if ( ! is_array( $certificates ) ) {
			$certificates = array( $certificates );
		}

		$formatted_certificates = array();
		foreach ( $certificates as $cert ) {
			if ( ! empty( trim( $cert ) ) ) {
				$formatted_certificates[] = self::normalize_certificate_format( trim( $cert ) );
			}
		}

		return $formatted_certificates;
	}

	/**
	 * Normalize certificate format to match metadata extraction format.
	 *
	 * This function takes any certificate input and formats it consistently
	 * with proper BEGIN/END markers and 64-character line breaks, matching
	 * the format used by metadata extraction in Metadata_Reader::extract_certificate().
	 *
	 * @param string $cert_data Raw certificate data.
	 * @return string Properly formatted certificate in PEM format.
	 */
	public static function normalize_certificate_format( $cert_data ) {
		$cert_data = str_replace( array( "\r", "\n", "\t", ' ' ), '', $cert_data );
		$cert_data = str_replace( '-----BEGIN CERTIFICATE-----', '', $cert_data );
		$cert_data = str_replace( '-----END CERTIFICATE-----', '', $cert_data );
		$cert_data = str_replace( '-----BEGINX509CERTIFICATE-----', '', $cert_data );
		$cert_data = str_replace( '-----ENDX509CERTIFICATE-----', '', $cert_data );
		$cert_data = str_replace( '-----BEGINCERTIFICATE-----', '', $cert_data );
		$cert_data = str_replace( '-----ENDCERTIFICATE-----', '', $cert_data );

		if ( ! empty( $cert_data ) ) {
			return '-----BEGIN CERTIFICATE-----' . "\n" . trim( chunk_split( $cert_data, 64, "\n" ) ) . "\n" . '-----END CERTIFICATE-----';
		}

		return '';
	}

	/**
	 * Save the SP certificate.
	 *
	 * @param string|int $id Environment ID.
	 * @return void
	 */
	public static function save_sp_certificate( $id = '' ) {
		$cert             = file_get_contents( plugin_dir_path( dirname( __DIR__, 1 ) ) . 'resource' . DIRECTORY_SEPARATOR . \MOSAML\SRC\Constant\Constants::SP_CERT_FILE_NAME );
		$cert_private_key = file_get_contents( plugin_dir_path( dirname( __DIR__, 1 ) ) . 'resource' . DIRECTORY_SEPARATOR . \MOSAML\SRC\Constant\Constants::SP_PRIVATE_KEY_FILE_NAME );
		$environment_id   = ! empty( $id ) ? $id : DB_Utils::get_environment_details( 'id', false );

		if ( get_option( 'mo_saml_cert' ) && get_option( 'mo_saml_cert_private_key' ) ) {
			DB_Utils::insert_or_update(
				Constants::DATABASE_TABLE_NAMES['sp_metadata'],
				array(
					'public_key'     => get_option( 'mo_saml_cert' ),
					'private_key'    => get_option( 'mo_saml_cert_private_key' ),
					'environment_id' => $environment_id,
				),
				array( 'environment_id' => $environment_id )
			);
		} else {
			DB_Utils::insert_or_update(
				Constants::DATABASE_TABLE_NAMES['sp_metadata'],
				array(
					'public_key'     => $cert,
					'private_key'    => $cert_private_key,
					'environment_id' => $environment_id,
				),
				array( 'environment_id' => $environment_id )
			);
		}
	}

	/**
	 * Desanitize the certificate.
	 *
	 * @param  string $certificate Contains value of certificate.
	 * @return string
	 */
	public static function desanitize_certificate( $certificate ) {
		$certificate = preg_replace( "/[\r\n]+/", '', $certificate );
		$certificate = str_replace( '-----BEGIN CERTIFICATE-----', '', $certificate );
		$certificate = str_replace( '-----END CERTIFICATE-----', '', $certificate );
		$certificate = str_replace( ' ', '', $certificate );
		return $certificate;
	}

	/**
	 * Sanitize the certificate.
	 *
	 * @param string $certificate Contains value of certificate.
	 * @return string Sanitized certificate.
	 */
	public static function sanitize_certificate( $certificate ) {

		$certificate = trim( $certificate );
		$certificate = preg_replace( "/[\r\n]+/", '', $certificate );
		$certificate = str_replace( '-', '', $certificate );
		$certificate = str_replace( 'BEGIN CERTIFICATE', '', $certificate );
		$certificate = str_replace( 'END CERTIFICATE', '', $certificate );
		$certificate = str_replace( ' ', '', $certificate );
		$certificate = chunk_split( $certificate, 64, "\r\n" );
		$certificate = "-----BEGIN CERTIFICATE-----\r\n" . $certificate . '-----END CERTIFICATE-----';
		return $certificate;
	}
}
