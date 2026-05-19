<?php
/**
 * This file is part of miniOrange WP plugin.
 *
 * @package    miniOrange
 * @author     miniOrange Security Software Pvt. Ltd.
 */

namespace MOSAML\LicenseLibrary\Handlers;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use Exception;
use MOSAML\LicenseLibrary\Classes\Mo_License_Constants;
use MOSAML\LicenseLibrary\Classes\Mo_License_Dao;
use MOSAML\LicenseLibrary\Exceptions\Mo_License_Already_Used_License_Key_Exception;
use MOSAML\LicenseLibrary\Exceptions\Mo_License_Invalid_License_Key_Exception;
use MOSAML\LicenseLibrary\Mo_License_Config;
use MOSAML\LicenseLibrary\Mo_License_Service;
use MOSAML\LicenseLibrary\Utils\Mo_License_Actions_Utility;
use MOSAML\LicenseLibrary\Utils\Mo_License_Backup_Code_Checker;
use MOSAML\LicenseLibrary\Utils\Mo_License_API_Utility;
use MOSAML\LicenseLibrary\Utils\Mo_License_Service_Utility;
use MOSAML\LicenseLibrary\Views\Mo_License_Notice_Views;

/**
 * Class Mo_License_Actions_Handler contains all callback functions for the
 * license framework hooks.
 */
class Mo_License_Actions_Handler {

	/**
	 * Stores plugin's license expiry date.
	 *
	 * @var string
	 */
	private $license_expiry_date;

	/**
	 * Instantiates the class objects required for self functioning.
	 *
	 * @param string $expiry_date The license expiry date.
	 */
	public function __construct( $expiry_date ) {
		$this->license_expiry_date = $expiry_date;
	}

	/**
	 * Function to update license information once every month.
	 *
	 * @return void
	 */
	public function run_license_cron() {

		if ( ! Mo_License_Service::is_customer_license_verified() ) {
			return;
		}

		$ln_check_t = Mo_License_Dao::mo_get_option( Mo_License_Constants::LAST_CHECK_TIME_OPTION );
		if ( $ln_check_t ) {
			$ln_check_t = intval( $ln_check_t );
			if ( time() - $ln_check_t < 3600 * 24 * $this->get_license_cron_interval() ) {
				return;
			}
		}

		$license_expiry_date = Mo_License_Actions_Utility::fetch_license_expiry_date();
		if ( $license_expiry_date ) {
			Mo_License_Service::update_license_expiry( $license_expiry_date );
			Mo_License_Dao::mo_update_option( Mo_License_Constants::LAST_CHECK_TIME_OPTION, time() );
		}
	}

	/**
	 * Checks and validates the license key and domain via backupcode/check cron.
	 *
	 * Uses the miniOrange backupcode/check API for periodic license and domain verification.
	 *
	 * @return void
	 */
	public function run_domain_check_cron() {

		if ( ! Mo_License_Config::DOMAIN_CHECK_CRON_ENABLED ) {
			return;
		}

		if ( ! Mo_License_Service::is_customer_license_verified() ) {
			return;
		}

		$dc_check_t = Mo_License_Dao::mo_get_option( Mo_License_Constants::LAST_DOMAIN_CHECK_TIME_OPTION );
		if ( $dc_check_t ) {
			$dc_check_t = intval( $dc_check_t );
			if ( time() - $dc_check_t < 3600 * 24 * Mo_License_Config::DOMAIN_CHECK_CRON_INTERVAL ) {
				return;
			}
		}

		try {
			Mo_License_Backup_Code_Checker::check_license();
		} catch ( Mo_License_Already_Used_License_Key_Exception $e ) {
			Mo_License_Dao::mo_update_option( Mo_License_Constants::DOMAIN_CHECK_FAILED_OPTION, Mo_License_Service_Utility::mo_encrypt_data( 'FAILED' ) );
			$failed_dn_t = Mo_License_Dao::mo_get_option( Mo_License_Constants::FAILED_DOMAIN_CHECK_TIME_OPTION );
			if ( $failed_dn_t ) {
				$failed_dn_t = intval( $failed_dn_t );
				if ( time() - $failed_dn_t > 3600 * 24 * Mo_License_Config::FAILED_DOMAIN_CRON_THRESHOLD ) {
					Mo_License_Service::free_license_key();
				}
			} else {
				Mo_License_Dao::mo_update_option( Mo_License_Constants::FAILED_DOMAIN_CHECK_TIME_OPTION, time() );
			}
		} catch ( Exception $e ) {
			//Error during license domain check
		}

		Mo_License_Dao::mo_update_option( Mo_License_Constants::LAST_DOMAIN_CHECK_TIME_OPTION, time() );
	}

	/**
	 * Will fetch the License Cron Interval based on the license expiry.
	 *
	 * @return int
	 */
	private function get_license_cron_interval() {
		$remaining_days = Mo_License_Service::get_expiry_remaining_days( $this->license_expiry_date );
		if ( $remaining_days >= 60 ) {
			return Mo_License_Config::LICENSE_CRON_INTERVAL['DEFAULT'];
		} elseif ( $remaining_days > 10 && $remaining_days < 60 ) {
			return Mo_License_Config::LICENSE_CRON_INTERVAL['EXPIRY_WITHIN_60_DAYS'];
		} elseif ( $remaining_days <= 10 ) {
			return Mo_License_Config::LICENSE_CRON_INTERVAL['EXPIRED_LICENSE'];
		}
	}

	/**
	 * Handles the dismiss of admin notice which displays license expiry information.
	 *
	 * @return void
	 */
	public function dismiss_admin_license_notice() {
		if ( current_user_can( 'manage_options' ) && ! empty( $_POST['option'] ) && Mo_License_Constants::ADMIN_NOTICE_DISMISS_ID === $_POST['option'] && check_admin_referer( Mo_License_Constants::ADMIN_NOTICE_DISMISS_ID ) ) {
			$remaining_days = Mo_License_Service::get_expiry_remaining_days( $this->license_expiry_date );
			Mo_License_Dao::mo_update_option( Mo_License_Constants::EXPIRY_NOTICE_CLOSE_OPTION, $remaining_days );
		}
	}

	/**
	 * Refreshes the license expiry information when refresh icon is clicked on the admin
	 * dashboard widget.
	 *
	 * @return void
	 */
	public function refresh_admin_widget_expiry() {
		if ( current_user_can( 'manage_options' ) && ! empty( $_POST['option'] ) && Mo_License_Constants::DASHBOARD_WIDGET_REFRESH_ID === $_POST['option'] && check_admin_referer( Mo_License_Constants::DASHBOARD_WIDGET_REFRESH_ID ) ) {
			Mo_License_Service::refresh_license_expiry();
		}
	}
}
