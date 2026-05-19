<?php
/**
 * Custom Certificate UI Handler
 *
 * This file contains the Custom_Certificate_UI_Handler class which handles the rendering
 * of the Manage Certificate tab UI.
 *
 * @package MOSAML
 */

namespace MOSAML\SRC\Handler\UI;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\SRC\Interfaces\Tab_UI_Handler_Interface;
use MOSAML\SRC\Constant\Plugin_Files_Constants;
use MOSAML\Module\Base\Handler\Admin\Certificate_Data_Handler;
use MOSAML\SRC\Utils\Certificate_Utility;
use MOSAML\SRC\Utils\DB_Utils;
use MOSAML\SRC\Utils\Utility;
use MOSAML\SRC\Utils\Feature_Control;

/**
 * Custom Certificate UI Handler
 *
 * Handles the rendering of the Manage Certificate tab UI by loading the required data
 * and including the template file.
 */
class Custom_Certificate_UI_Handler implements Tab_UI_Handler_Interface {

	/**
	 * Render the Manage Certificate tab UI.
	 *
	 * @return void
	 */
	public function render_ui() {
		$custom_certificate_data = new Certificate_Data_Handler();
		$custom_certificate_data = $custom_certificate_data->get_data();
		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- Reading a local plugin resource file.
		$certificate_file                  = file_get_contents( MOSAML_PLUGIN_DIR . 'resource' . DIRECTORY_SEPARATOR . \MOSAML\SRC\Constant\Constants::SP_CERT_FILE_NAME );
		$remaining_days_for_db_certificate = Certificate_Utility::get_remaining_days_of_certificate( $custom_certificate_data->public_key );
		$remaining_days_certificate_file   = Certificate_Utility::get_remaining_days_of_certificate( $certificate_file );
		$valid_to_time                     = Certificate_Utility::get_expiry_date_of_certificate( $custom_certificate_data->public_key );
		$valid_to                          = $valid_to_time > 0 ? gmdate( 'D, d M Y ', $valid_to_time ) : '';
		$enable_custom_certificate         = $custom_certificate_data->is_custom_certificate ? ' active-cert' : '';
		$enable_miniorange_certificate     = '' === $enable_custom_certificate ? ' active-cert' : '';
		$thumbprint                        = ( ! empty( $custom_certificate_data->public_key ) && is_string( $custom_certificate_data->public_key ) )
			? openssl_x509_fingerprint( $custom_certificate_data->public_key, 'sha1' ) : '';
		if ( false === $thumbprint ) {
			$thumbprint = '';
		}
		$private_cert                      = $custom_certificate_data->is_custom_certificate ? $custom_certificate_data->private_key : '';
		$public_cert                       = $custom_certificate_data->is_custom_certificate ? $custom_certificate_data->public_key : '';
		$disable_upgrade_tab               = $remaining_days_for_db_certificate < 60;
		$cert_idp_name                     = get_option( 'mo_saml_cert_idp_name' ) ? get_option( 'mo_saml_cert_idp_name' ) : 'DEFAULT';
		$style_value                       = $custom_certificate_data->is_custom_certificate ? 'none' : 'block';
		$enable_custom_certificate_display = $custom_certificate_data->is_custom_certificate ? 'block' : 'none';
		$identity_providers                = DB_Utils::get_configured_idps_details( '', false, true );
		$display_upgrade_certificate_steps = 'block';
		$disabled_due_to_license           = Utility::mo_saml_get_disabled_attribute( ! Feature_Control::free_or_license_specific_feature_enabled() );

		require_once Plugin_Files_Constants::TEMPLATE_CUSTOM_CERTIFICATE;
	}
}
