<?php
/**
 * SP Endpoints Data Handler file for standard plan.
 *
 * @package MOSAML\Module\Standard\Handler\Admin
 */

namespace MOSAML\Module\Standard\Handler\Admin;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\Module\Base\Handler\Admin\SP_Endpoints_Data_Handler as Base_SP_Endpoints_Data_Handler;
use MOSAML\SRC\Interfaces\Form_Data_Handler_Interface;
use MOSAML\SRC\Utils\Error_Success_Message;

/**
 * SP Endpoints Data Handler class for standard plan.
 */
class SP_Endpoints_Data_Handler extends Base_SP_Endpoints_Data_Handler implements Form_Data_Handler_Interface {

	/**
	 * Validate and save the sp endpoints data.
	 *
	 * @return void
	 */
	public function validate_and_save_data() {

        // phpcs:ignore WordPress.Security.NonceVerification.Missing,WordPress.Security.ValidatedSanitizedInput.MissingUnslash,WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Nonce Verification is done from mo_check_option_admin_referer function.
		$this->sp_base_url = ! empty( $_POST['mo_saml_sp_base_url'] ) ? esc_url_raw( filter_var( $_POST['mo_saml_sp_base_url'], FILTER_SANITIZE_URL ) ) : '';

		if ( substr( $this->sp_base_url, -1 ) === '/' ) {
			$this->sp_base_url = substr( $this->sp_base_url, 0, -1 );
		}

		if ( empty( $this->sp_base_url ) ) {
			Error_Success_Message::show_admin_notice( 'Please enter a valid SP Base URL or SP Entity ID/Issuer.' );
			return;
		}

		parent::validate_and_save_data();
	}
}
