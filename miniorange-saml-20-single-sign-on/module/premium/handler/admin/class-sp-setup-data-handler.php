<?php
/**
 * SP Setup Handler.
 *
 * @package miniorange-saml-20-single-sign-on/module/premium/handler/admin
 */

namespace MOSAML\Module\Premium\Handler\Admin;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\Module\Standard\Handler\Admin\SP_Setup_Data_Handler as Standard_SP_Setup_Data_Handler;
use MOSAML\SRC\Interfaces\Form_Data_Handler_Interface;
use MOSAML\SRC\Utils\Utility;
use MOSAML\SRC\Utils\Error_Success_Message;
use MOSAML\SRC\Constant\Constants;
use MOSAML\SRC\Utils\DB_Utils;

/**
 * SP Setup Handler.
 */
class SP_Setup_Data_Handler extends Standard_SP_Setup_Data_Handler implements Form_Data_Handler_Interface {

	/**
	 * Apply version-specific settings to the data object.
	 * Premium version specific settings.
	 *
	 * @return void
	 */
	public function validate_and_save_data() {
		$upload_metadata = Utility::sanitize_post_data( 'upload_metadata' );
		if ( 'url' === $upload_metadata || 'file' === $upload_metadata ) {
			$this->handle_upload_metadata(
				array(
					'slo_service'  => true,
					'sign_request' => true,
				)
			);

		} elseif ( 'manual' === $upload_metadata ) {
			$this->slo_url            = Utility::sanitize_post_data( 'saml_logout_url' );
			$this->slo_response_url   = Utility::sanitize_post_data( 'saml_logout_response_url' );
			$this->password_reset_url = Utility::sanitize_post_data( 'saml_password_reset_url' );
			$this->slo_binding        = Utility::sanitize_post_data( 'saml_logout_binding_type' );
		}
		parent::validate_and_save_data();

		// phpcs:ignore WordPress.Security.NonceVerification.Missing,WordPress.Security.ValidatedSanitizedInput.MissingUnslash,WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Nonce Verification is done from mo_check_option_admin_referer function.
		if ( ! array_key_exists( 'sync_metadata', $_POST ) ) {
			return;
		}

		$this->sync_metadata         = Utility::sanitize_post_data( 'sync_metadata' );
		$this->metadata_url          = Utility::sanitize_post_data( 'metadata_url' );
		$this->sync_only_certificate = Utility::sanitize_post_data( 'sync_certificate_metadata' );
		$this->sync_time_interval    = Utility::sanitize_post_data( 'sync_time_interval' );
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
		} else {
			Utility::disable_metadata_sync( $this );
		}
		$sync_metadata_variables = array_intersect_key( get_object_vars( $this ), array_flip( array( 'sync_metadata', 'metadata_url', 'sync_time_interval', 'sync_only_certificate' ) ) );
		DB_Utils::insert_or_update(
			$this->get_table_name(),
			$sync_metadata_variables,
			array(
				'idp_id'         => $this->idp_id,
				'environment_id' => $this->environment_id,
			)
		);
	}
}
