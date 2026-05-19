<?php
/**
 * This file contains a handler for grace period popup.
 *
 * @package miniorange-saml-20-single-sign-on/handlers
 */

namespace MOSAML\SRC\Handler;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}
use MOSAML\SRC\Constant\Constants;
use MOSAML\SRC\Constant\Plugin_Files_Constants;
use MOSAML\SRC\Utils\Utility;
use MOSAML\Traits\Instance;

/**
 * Class to handle license expiry page.
 */
class License_Expiry_Page_Handler {
	/**
	 * Instance of this class
	 *
	 * @var License_Expiry_Page_Handler
	 */
	use Instance;

	/**
	 * Sets the popup flag for the current user
	 *
	 * @param boolean $popup_value The value of the popup flag.
	 * @return void
	 */
	public function update_popup_flag( $popup_value ) {
		update_user_meta( get_current_user_id(), 'mosaml_show_license_expiry_page', $popup_value );
	}

	/**
	 * Gets the popup flag for the current user
	 *
	 * @return boolean The value of the popup flag.
	 */
	public function get_popup_flag() {
		return ! empty( get_user_meta( get_current_user_id(), 'mosaml_show_license_expiry_page', true ) );
	}

	/**
	 * Displays the grace period popup
	 *
	 * @return void
	 */
	public function handle_license_expiry_page() {
		if ( ! Utility::handle_license_calls( 'is_license_verified', 'library', false ) ) {
			return;
		}

		if ( wp_doing_ajax() ) {
			return;
		}

		$license_status = Utility::handle_license_calls( 'is_license_expired', 'library', false );
		if ( ! $license_status['STATUS'] && 'LICENSE_IN_GRACE' !== $license_status['CODE'] ) {
			return;
		}

		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- No nonce verification needed since we are not processing any form data here.
		if ( ! is_user_logged_in() || ! current_user_can( 'manage_options' ) || ( true === $this->get_popup_flag() && 'LICENSE_IN_GRACE' === $license_status['CODE'] ) || ( isset( $_GET['action'] ) && 'logout' === $_GET['action'] ) ) {
			return;
		}

		$this->display_license_expiry_page( $license_status );
		if ( ! $license_status['STATUS'] && 'LICENSE_IN_GRACE' === $license_status['CODE'] ) {
			$this->update_popup_flag( true );
		}
	}

	/**
	 * Displays the license expiry page
	 *
	 * @param array $license_status The license status.
	 * @return void
	 */
	public function display_license_expiry_page( $license_status ) {
		$mo_logo_url             = esc_url_raw( plugin_dir_url( MOSAML_PLUGIN_FILE ) . 'static/image/miniorange-logo.png' );
		$success_icon_url        = esc_url_raw( plugin_dir_url( MOSAML_PLUGIN_FILE ) . 'static/image/green_check.webp' );
		$error_icon_url          = esc_url_raw( plugin_dir_url( MOSAML_PLUGIN_FILE ) . 'static/image/wrong.webp' );
		$grace_notice_style_url  = esc_url_raw( plugin_dir_url( MOSAML_PLUGIN_FILE ) . 'static/css/license-expiry-page.css' );
		$grace_notice_script_url = esc_url_raw( plugin_dir_url( MOSAML_PLUGIN_FILE ) . 'static/js/license-expiry-page.js' );

		wp_enqueue_style( 'mosaml_grace_notice_style', $grace_notice_style_url, array(), Constants::VERSION_NUMBER[ MOSAML_VERSION ], false );
		wp_enqueue_script( 'mosaml_grace_notice_script', $grace_notice_script_url, array( 'jquery' ), Constants::VERSION_NUMBER[ MOSAML_VERSION ], false );

		$grace_notice_script_data = array(
			'ajax_url'         => admin_url( 'admin-ajax.php' ),
			'nonce'            => wp_create_nonce( 'mosaml_grace_notice_nonce' ),
			'renewal_faq_url'  => esc_url_raw( Utility::get_renewal_faq_url() ),
			'account_info_url' => add_query_arg(
				array(
					'page' => 'mo_saml_settings',
					'tab'  => 'account_settings',
				),
				admin_url( 'admin.php' )
			),
			'success_icon'     => $success_icon_url,
			'error_icon'       => $error_icon_url,
		);

		if ( ! empty( $license_status['STATUS'] ) && 'LICENSE_GRACE_EXPIRED' === ( $license_status['CODE'] ?? '' ) ) {
			$grace_notice_script_data['redirect_after_grace_expired_notice'] = true;
			$grace_notice_script_data['plugins_page_url']                    = admin_url( 'plugins.php' );
		}

		wp_localize_script(
			'mosaml_grace_notice_script',
			'mosaml_grace_notice_data',
			$grace_notice_script_data
		);
		require_once Plugin_Files_Constants::TEMPLATE_LICENSE_EXPIRY_PAGE;
	}
}
