<?php
/**
 * Account Settings UI Handler.
 *
 * @package miniorange-saml-20-single-sign-on
 */

namespace MOSAML\SRC\Handler\UI;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\LicenseLibrary\Mo_License_Config;
use MOSAML\LicenseLibrary\Utils\Mo_License_Service_Utility;
use MOSAML\SRC\Interfaces\Tab_UI_Handler_Interface;
use MOSAML\SRC\Constant\Plugin_Files_Constants;
use MOSAML\SRC\Utils\Utility;
use MOSAML\SRC\Constant\Constants;

/**
 * Class Account_Settings_UI_Handler
 *
 * Handles the rendering of the Account Info tab UI.
 */
class Account_Settings_UI_Handler implements Tab_UI_Handler_Interface {

	/**
	 * Render the UI.
	 *
	 * @return void
	 */
	public function render_ui() {

		$account_verified = Utility::handle_license_calls( 'is_account_verified', 'library', false );
		$license_verified = Utility::handle_license_calls( 'is_license_verified', 'library', true );
		$is_free          = Utility::handle_license_calls( 'is_free', 'library', true );
		$active_subtab    = ! empty( Utility::sanitize_get_data( 'subtab' ) ) ? Utility::sanitize_get_data( 'subtab' ) : 'account-login';

		if ( ! $account_verified ) {
			if ( 'account-register' === $active_subtab && $is_free ) {
				require_once Plugin_Files_Constants::TEMPLATE_ACCOUNT_REGISTRATION;
			} else {
				require_once Plugin_Files_Constants::TEMPLATE_ACCOUNT_LOGIN;
			}
		} elseif ( ! $is_free && ! $license_verified ) {
			require_once Plugin_Files_Constants::TEMPLATE_LICENSE_VERIFICATION;
		} elseif ( $account_verified && $license_verified ) {
			if ( ! $is_free ) {
				$this->get_account_info();
			} else {
				$customer_id    = get_option( 'mo_saml_admin_customer_key' );
				$customer_email = get_option( 'mo_saml_admin_email' );
				require_once Plugin_Files_Constants::TEMPLATE_ACCOUNT_INFO_FREE;
			}
		}
	}

	/**
	 * Get account info.
	 *
	 * @return void
	 */
	public function get_account_info() {
		$customer_id             = get_option( 'mo_saml_admin_customer_key' );
		$customer_email          = get_option( 'mo_saml_admin_email' );
		$unformatted_expiry_date = Utility::handle_license_calls( 'get_expiry_date', 'library', '' );
		$expiry_date             = Utility::handle_license_calls( 'get_formatted_license_expiry_date', 'library', '', $unformatted_expiry_date );
		$disable_date            = Utility::handle_license_calls( 'get_disable_date', 'library', '', $expiry_date );
		$remaining_days          = Utility::handle_license_calls( 'get_remaining_days', 'library', 0, $expiry_date );
		$grace_days              = Utility::handle_license_calls( 'get_grace_days_left', 'library', 0, $expiry_date );
		$vl_check_t              = gmdate( 'M d, Y H:i:s', Utility::handle_license_calls( 'get_last_synced_time', 'library', '' ) );
		$expiry_notice_class     = $this->get_expiry_notice_class( $remaining_days );
		$content_options         = array(
			'##remaining_days##'  => $remaining_days,
			'##expiry_date##'     => $expiry_date,
			'##disable_date##'    => $disable_date,
			'##grace_days_left##' => $grace_days,
			'##customer_email##'  => $customer_email,
		);
		if ( $remaining_days <= 60 && $customer_email && $customer_id ) {
			$box_expiry_heading = $this->get_box_expiry_notice_heading( $content_options );
		}
		$notice_day_key      = Utility::handle_license_calls( 'get_notice_day_key', 'library', '', $remaining_days );
		$plugin_notice       = Utility::handle_license_calls( 'get_admin_notice_html', 'library', '', $notice_day_key, $content_options );
		$escaped_notice_html = $this->get_escaped_license_content( $plugin_notice );
		$license_valid_attr  = Utility::handle_license_calls( 'is_license_valid', 'library', false, true, false );
		$no_of_sp_option_key = Mo_License_Config::LICENSE_OPTIONS['noOfSP'];
		$encrypted_idp_limit = get_option( $no_of_sp_option_key, '' );
		$idp_limit_raw       = class_exists( Mo_License_Service_Utility::class ) ? Mo_License_Service_Utility::mo_decrypt_data( $encrypted_idp_limit ) : $encrypted_idp_limit;
		$allowed_idp_count   = is_numeric( $idp_limit_raw ) ? max( 1, (int) $idp_limit_raw ) : 1;
		$renewal_faq_url     = Constants::RENEWAL_FAQ_URL;
		$generic_faq_url     = 'https://plugins.miniorange.com/wordpress-single-sign-on-sso#pricing-faqs';
		$license_faq_answer  = $this->get_license_faq_answer( $expiry_date );
		require_once Plugin_Files_Constants::TEMPLATE_ACCOUNT_INFO;
	}

	/**
	 * Get box expiry notice heading.
	 *
	 * @param array $content_options Content options array.
	 * @return string
	 */
	public function get_box_expiry_notice_heading( $content_options ) {
		$heading = '';

		$is_license_expired = Utility::handle_license_calls( 'is_license_expired', 'library', false );

		if ( ! empty( $is_license_expired['STATUS'] ) && true === $is_license_expired['STATUS'] ) {
			$heading = 'Warning : Your SSO has stopped working. Renew your license now!';
		} elseif ( ! empty( $is_license_expired['STATUS'] ) && false === $is_license_expired['STATUS'] && ! empty( $is_license_expired['CODE'] ) && 'LICENSE_IN_GRACE' === $is_license_expired['CODE'] ) {
			$heading = 'Your plugin has expired and SSO will stop working in <span id="mo_saml_profile_box_counter">' . esc_html( $content_options['##grace_days_left##'] ) . '</span> days. Renew your license now to avoid disruption.';
		} elseif ( $content_options['##remaining_days##'] <= 60 && $content_options['##remaining_days##'] > 0 ) {
			$heading = 'License Expiry Notice : Plugin License getting expired in <span id="mo_saml_profile_box_counter"> ' . esc_html( $content_options['##remaining_days##'] ) . ' </span> days';
		} elseif ( 0 === (int) $content_options['##remaining_days##'] ) {
			$heading = 'License Expiry Notice : Your License expired today. Renew your license now!';
		} elseif ( $content_options['##remaining_days##'] < 0 ) {
			$days_ago = abs( intval( $content_options['##remaining_days##'] ) );
			$heading  = 'License Expiry Notice : Plugin License expired <span id="mo_saml_profile_box_counter"> ' . esc_html( $days_ago ) . ' </span> days ago';
		}

		return $heading;
	}

	/**
	 * Determines the CSS class for the expiry notice based on the remaining days.
	 *
	 * @param int $remaining_days The number of remaining days.
	 *
	 * @return string The CSS class for the expiry notice.
	 */
	public function get_expiry_notice_class( $remaining_days ) {
		if ( $remaining_days < 60 && $remaining_days > 0 ) {
			return 'mo-saml-warning-yellow';
		} elseif ( $remaining_days <= 0 && $remaining_days > -15 ) {
			return 'mo-saml-warning-orange';
		} elseif ( $remaining_days <= -15 ) {
			return 'mo-saml-warning-red';
		}
		return '';
	}

	/**
	 * Get license FAQ answer.
	 *
	 * @param string $expiry_date The expiry date.
	 * @return string The license FAQ answer.
	 */
	public function get_license_faq_answer( $expiry_date ) {
		$current_date          = gmdate( 'Y-m-d' );
		$expiry_date_timestamp = strtotime( $expiry_date );
		$expiry_date_formatted = gmdate( 'Y-m-d', $expiry_date_timestamp );

		if ( $expiry_date && $expiry_date_formatted >= $current_date ) {
			$message = 'Your License is due to expire on';
		} else {
			$message = 'Your License has already expired on';
		}

		return $message;
	}

	/**
	 * Function to get escaped content of the license expiry warning notice shown in the Account Info tab.
	 *
	 * @param array $plugin_notice Contains warning content to be shown for license expiry.
	 * @return string
	 */
	public function get_escaped_license_content( $plugin_notice ) {
		$html = '
		<div>
			<h3>' . esc_html( $plugin_notice['heading'] ) . '</h3>
			<div>' .
					wp_kses(
						$plugin_notice['content'],
						array(
							'p' => array(),
							'b' => array(),
							'u' => array(),
							'a' => array(
								'href'   => array(),
								'target' => array(),
							),
						)
					) . ' 
			</div>
		</div>';
		return $html;
	}
}
