<?php
/**
 * Custom Certificate Data Handler file for premium plan.
 *
 * @package MOSAML\Module\Premium\Handler\Admin
 */

namespace MOSAML\Module\Premium\Handler\Admin;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\Module\Standard\Handler\Admin\Certificate_Data_Handler as Standard_Certificate_Data_Handler;
use MOSAML\SRC\Constant\Constants;
use MOSAML\SRC\Utils\Error_Success_Message;
use MOSAML\SRC\Interfaces\Form_Data_Handler_Interface;
use MOSAML\SRC\Utils\Certificate_Utility;
use MOSAML\SRC\Utils\Utility;
use MOSAML\SRC\Utils\DB_Utils;

/**
 * Custom Certificate Data Handler class for premium plan.
 */
class Certificate_Data_Handler extends Standard_Certificate_Data_Handler implements Form_Data_Handler_Interface {

	/**
	 * Validate and save the custom certificate data.
	 *
	 * @return void
	 */
	public function validate_and_save_data() {

		if ( 'Upload' === Utility::sanitize_post_data( 'submit' ) ) {

			// phpcs:ignore WordPress.Security.NonceVerification.Missing,WordPress.Security.ValidatedSanitizedInput.MissingUnslash,WordPress.Security.ValidatedSanitizedInput.InputNotSanitized,WordPress.Security.ValidatedSanitizedInput.InputNotValidated -- Nonce Verification is done from mo_check_option_admin_referer function.
			$public_cert = $_POST['saml_public_x509_certificate'];
			// phpcs:ignore WordPress.Security.NonceVerification.Missing,WordPress.Security.ValidatedSanitizedInput.MissingUnslash,WordPress.Security.ValidatedSanitizedInput.InputNotSanitized,WordPress.Security.ValidatedSanitizedInput.InputNotValidated -- Nonce Verification is done from mo_check_option_admin_referer function.
			$private_cert = $_POST['saml_private_x509_certificate'];

			// phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_set_error_handler -- Needed to prevent OpenSSL warnings.
			set_error_handler(
				static function ( $errno, $errstr ) {
					unset( $errno, $errstr );
					return true;
				}
			);
			$x509 = openssl_x509_read( $public_cert );
			restore_error_handler();

			$cert_valid = false !== $x509;

			// phpcs:ignore WordPress.Security.NonceVerification.Missing,WordPress.Security.ValidatedSanitizedInput.MissingUnslash,WordPress.Security.ValidatedSanitizedInput.InputNotSanitized,WordPress.Security.ValidatedSanitizedInput.InputNotValidated -- Nonce Verification is done from mo_check_option_admin_referer function.
			if ( ! $cert_valid || Certificate_Utility::get_remaining_days_of_certificate( $public_cert ) < 1 ) {

				Error_Success_Message::show_admin_notice( 'Either Invalid Certificate format or Certificate expired. Please enter a valid certificate.' );
				return;
			}

			// phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_set_error_handler -- Needed to prevent OpenSSL warnings.
			set_error_handler(
				static function ( $errno, $errstr ) {
					unset( $errno, $errstr );
					return true;
				}
			);
			$key_matches_cert = openssl_x509_check_private_key( $public_cert, $private_cert );
			restore_error_handler();

			if ( ! $key_matches_cert ) {
				Error_Success_Message::show_admin_notice( 'Invalid Private Key.' );
				return;
			}

			$this->public_key            = $public_cert;
			$this->private_key           = $private_cert;
			$this->is_custom_certificate = 1;

			DB_Utils::insert_or_update(
				Constants::DATABASE_TABLE_NAMES['idp_details'],
				array(
					'environment_id' => DB_Utils::get_environment_details( 'id', false ),
					'sp_certificate' => $this->public_key,
					'sp_private_key' => $this->private_key,
				),
				array( 'environment_id' => DB_Utils::get_environment_details( 'id', false ) )
			);
		} elseif ( 'Reset' === Utility::sanitize_post_data( 'submit' ) ) {
			// phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- Reading a local plugin resource file.
			$this->public_key = file_get_contents( plugin_dir_path( dirname( __DIR__, 3 ) ) . 'resource' . DIRECTORY_SEPARATOR . \MOSAML\SRC\Constant\Constants::SP_CERT_FILE_NAME );
			// phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- Reading a local plugin resource file.
			$this->private_key           = file_get_contents( plugin_dir_path( dirname( __DIR__, 3 ) ) . 'resource' . DIRECTORY_SEPARATOR . \MOSAML\SRC\Constant\Constants::SP_PRIVATE_KEY_FILE_NAME );
			$this->is_custom_certificate = 0;

			DB_Utils::insert_or_update(
				Constants::DATABASE_TABLE_NAMES['idp_details'],
				array(
					'environment_id' => DB_Utils::get_environment_details( 'id', false ),
					'sp_certificate' => $this->public_key,
					'sp_private_key' => $this->private_key,
				),
				array( 'environment_id' => DB_Utils::get_environment_details( 'id', false ) )
			);
		}
		parent::validate_and_save_data();
	}
}
