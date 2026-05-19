<?php
/**
 * This file is part of miniOrange WP plugin.
 *
 * @package    miniOrange
 * @author     miniOrange Security Software Pvt. Ltd.
 */

namespace MOSAML\LicenseLibrary\Utils;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\LicenseLibrary\Classes\Mo_License_Constants;
use MOSAML\LicenseLibrary\Classes\Mo_License_Dao;
use MOSAML\LicenseLibrary\Mo_License_Config;
use MOSAML\LicenseLibrary\Mo_License_Service;

/**
 * Mo_License_View_Utility class contains utility functions for license notices.
 */
class Mo_License_View_Utility {

	/**
	 * Determines the notice class for license expiry admin notice.
	 *
	 * @param int $remaining_days The number of remaining days.
	 *
	 * @return string The notice class for the expiry admin notice.
	 */
	public static function get_expiry_admin_notice_class( $remaining_days ) {
		if ( $remaining_days > 10 ) {
			return 'notice-warning';
		} elseif ( $remaining_days <= 10 ) {
			return 'notice-error';
		}
		return '';
	}

	/**
	 * Function to get the content for the license information admin notice.
	 *
	 * @param string $day_key The day for which the content is to be shown. This value
	 * is fetched from get_notice_day_key().
	 * @param array  $content_options Array of values required to be displayed in the
	 *      license admin notice.
	 *
	 * @return array
	 */
	public static function get_admin_notice_html( $day_key, $content_options ) {

		$html            = Mo_License_Config::$notice_html[ $day_key ];
		$html['content'] = strtr( $html['content'], $content_options );
		return $html;
	}

	/**
	 * Function to get the day number for displaying notice content accordingly.
	 *
	 * @param int $remaining_days The number of days remaining for license expiry.
	 *
	 * @return int|bool|string
	 */
	public static function get_notice_day_key( $remaining_days ) {

		if ( Mo_License_Service::is_trial_license() ) {
			if ( $remaining_days > 0 ) {
				return Mo_License_Constants::TRIAL_PERIOD_STARTED;
			} else {
				return Mo_License_Constants::TRIAL_PERIOD_EXPIRED;
			}
		}

		if ( $remaining_days <= 60 && $remaining_days > 30 ) {
			return Mo_License_Constants::EXPIRY_IN_30_TO_60_DAYS;
		} elseif ( $remaining_days <= 30 && $remaining_days > 10 ) {
			return Mo_License_Constants::EXPIRY_IN_10_TO_30_DAYS;
		} elseif ( $remaining_days <= 10 && $remaining_days >= 0 ) {
			return Mo_License_Constants::EXPIRY_IN_10_DAYS;
		} elseif ( $remaining_days < 0 && $remaining_days >= - ( Mo_License_Config::GRACE_PERIOD_DAYS ) ) {
			return Mo_License_Constants::GRACE_PERIOD_STARTED;
		} elseif ( $remaining_days < - ( Mo_License_Config::GRACE_PERIOD_DAYS ) ) {
			return Mo_License_Constants::GRACE_PERIOD_EXPIRED;
		}
		return false;
	}

	/**
	 * Function to get the notice that has to be added on the widget when license is
	 * going to expire in 60 days.
	 *
	 * @param array $content_options Contains values of options required to be displayed
	 * in the license dahsboard widget.
	 *
	 * @return string
	 */
	public static function get_widget_notice( $content_options ) {

		$notice             = '';
		$is_license_expired = Mo_License_Service::is_license_expired();

		if ( Mo_License_Service::is_trial_license() ) {
			if ( true === $is_license_expired['STATUS'] ) {
				$notice = 'Your trial plugin license has expired. Please purchase the plugin to continue with seamless SSO experience.';
			} else {
				$notice = 'You are currently on trial plugin license. Please purchase the plugin to continue with seamless SSO experience.';
			}
		} elseif ( true === $is_license_expired['STATUS'] ) {
			$notice = 'Your plugin license has expired and the plugin has stopped working. Please <a href="' . Mo_License_Config::RENEWAL_FAQ . '" target="_blank">renew your license</a> immediately.';
		} elseif ( false === $is_license_expired['STATUS'] && 'LICENSE_IN_GRACE' === $is_license_expired['CODE'] ) {
			$notice = 'You are currently on grace period for renewal. ' . esc_html( $content_options['##grace_days_left##'] ) . ' days left before SSO is disabled on your site.';
		} elseif ( $content_options['##remaining_days##'] < 60 ) {
			$notice = 'Your plugin license is going to expire in ' . esc_html( $content_options['##remaining_days##'] ) . ' days';
		}

		return $notice;
	}

	/**
	 * Function to check if plugin expiry admin notice should be shown. If yes, returns true. Else returns false.
	 * Intakes the remaining days of license expiry and checks if notice has been dismissed. Notice will be shown
	 * only if remaining days of expiry are less than 60 days, and the notice cannot be dismissed after remaining
	 * days of expiry is less than 10 days.
	 *
	 * @param int $remaining_days Contains number of days remaining for license expiry.
	 *
	 * @return bool
	 */
	public static function show_expiry_notice( $remaining_days ) {

		$dismiss = Mo_License_Dao::mo_get_option( Mo_License_Constants::EXPIRY_NOTICE_CLOSE_OPTION );

		if ( ! isset( $remaining_days ) || $remaining_days > 60 ) {
			return false;
		} elseif ( $remaining_days <= 10 ) {
			return true;
		} elseif ( ! $dismiss && $remaining_days <= 60 ) {
			return true;
		} elseif ( $dismiss && $dismiss > 30 && $remaining_days <= 30 ) {
			return true;
		}

		return false;
	}
}