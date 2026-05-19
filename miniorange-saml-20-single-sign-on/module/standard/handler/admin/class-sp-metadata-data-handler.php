<?php
/**
 * SP Metadata Data Handler file.
 *
 * @package MOSAML\Module\Standard\Handler\Admin
 */

namespace MOSAML\Module\Standard\Handler\Admin;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\Module\Base\Handler\Admin\SP_Metadata_Data_Handler as Base_SP_Metadata_Data_Handler;
use MOSAML\SRC\Utils\Certificate_Utility;

/**
 * Contains the download and display functionalities for SP Metadata.
 */
class SP_Metadata_Data_Handler extends Base_SP_Metadata_Data_Handler {
	/**
	 * Function to download the SP Metadata.
	 *
	 * @param bool $is_new_certificate Whether to use the new certificate.
	 */
	public function download_sp_metadata( $is_new_certificate = false ) {
		$this->set_certificate_node( $is_new_certificate );
		parent::download_sp_metadata( $is_new_certificate );
	}

	/**
	 * Function to display the SP Metadata.
	 */
	public function display_sp_metadata() {
		$this->set_certificate_node();
		parent::display_sp_metadata();
	}

	/**
	 * Function to download the SP Certificate.
	 *
	 * @param bool $is_new_certificate Whether to use the new certificate.
	 */
	public function download_certificate( $is_new_certificate = false ) {
		header( 'Content-Type: application/crt' );
		if ( $is_new_certificate ) {
			$filename = 'new-sp-certificate.crt';

			$new_sp_cert_file = plugin_dir_path( dirname( __DIR__, 3 ) ) . 'resource' . DIRECTORY_SEPARATOR . \MOSAML\SRC\Constant\Constants::NEW_SP_CERT_FILE_NAME;
			if ( file_exists( $new_sp_cert_file ) ) {
				// phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- Reading a local plugin resource file.
				$this->sp_certificate->public_key = file_get_contents( $new_sp_cert_file );
			}
		} else {
			$filename = 'sp-certificate.crt';
		}
		header( 'Content-Disposition: attachment; filename="' . $filename . '"' );

		if ( empty( $this->sp_certificate->public_key ) ) {
			// phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- Reading a local plugin resource file.
			$this->sp_certificate->public_key = file_get_contents( plugin_dir_path( dirname( __DIR__, 3 ) ) . 'resource' . DIRECTORY_SEPARATOR . \MOSAML\SRC\Constant\Constants::SP_CERT_FILE_NAME );
		}
		echo esc_attr( $this->sp_certificate->public_key );
		exit;
	}

	/**
	 * Function to set the SP Certificate node.
	 *
	 * @param bool $is_new_certificate Whether to use the new certificate.
	 */
	private function set_certificate_node( $is_new_certificate = false ) {
		if ( $is_new_certificate ) {
			$new_sp_cert_file = plugin_dir_path( dirname( __DIR__, 3 ) ) . 'resource' . DIRECTORY_SEPARATOR . \MOSAML\SRC\Constant\Constants::NEW_SP_CERT_FILE_NAME;
			if ( file_exists( $new_sp_cert_file ) ) {
				// phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- Reading a local plugin resource file.
				$this->sp_certificate->public_key = file_get_contents( $new_sp_cert_file );
			}
		}
		if ( empty( $this->sp_certificate->public_key ) ) {
			// phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- Reading a local plugin resource file.
			$this->sp_certificate->public_key = file_get_contents( plugin_dir_path( dirname( __DIR__, 3 ) ) . 'resource' . DIRECTORY_SEPARATOR . \MOSAML\SRC\Constant\Constants::SP_CERT_FILE_NAME );
		}
		$certificate_file              = $this->sp_certificate->public_key;
		$this->certificate_expiry_date = Certificate_Utility::get_expiry_date_of_certificate( $certificate_file );

		$certificate               = Certificate_Utility::desanitize_certificate( $certificate_file );
		$this->certificate_node    = (
			'<md:KeyDescriptor use="signing">
		<ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
			<ds:X509Data>
			<ds:X509Certificate>' . esc_attr( $certificate ) . '</ds:X509Certificate>
			</ds:X509Data>
		</ds:KeyInfo>
		</md:KeyDescriptor>
		<md:KeyDescriptor use="encryption">
		<ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
			<ds:X509Data>
			<ds:X509Certificate>' . esc_attr( $certificate ) . '</ds:X509Certificate>
			</ds:X509Data>
		</ds:KeyInfo>
		</md:KeyDescriptor>'
		);
		$this->name_id_format_node = (
			'<md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat>
		<md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:persistent</md:NameIDFormat>
		<md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</md:NameIDFormat>'
		);
	}
}
