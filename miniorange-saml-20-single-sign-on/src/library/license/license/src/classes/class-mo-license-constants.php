<?php
/**
 * This file is part of miniOrange WP plugin.
 *
 * @package    miniOrange
 * @author     miniOrange Security Software Pvt. Ltd.
 */

namespace MOSAML\LicenseLibrary\Classes;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\LicenseLibrary\Mo_License_Config;

/**
 * Contains constants used in the License Library.
 */
class Mo_License_Constants {

	const VERSION    = '1.1.0';
	const EPOCH_DATE = 'January 1, 1970';

	const LAST_CHECK_TIME_OPTION          = Mo_License_Config::OPTION_PREFIX . 'ln_check_t';
	const LAST_DOMAIN_CHECK_TIME_OPTION   = Mo_License_Config::OPTION_PREFIX . 'dn_check_t';
	const DOMAIN_CHECK_FAILED_OPTION      = Mo_License_Config::OPTION_PREFIX . 'dc_failed';
	const FAILED_DOMAIN_CHECK_TIME_OPTION = Mo_License_Config::OPTION_PREFIX . 'dc_failed_time';
	const LICENSE_EXPIRY_DATE_OPTION      = Mo_License_Config::OPTION_PREFIX . 'led';
	const EXPIRY_NOTICE_CLOSE_OPTION      = Mo_License_Config::OPTION_PREFIX . 'exp_notice_close';
	const LICENSE_EXPIRED_OPTION          = Mo_License_Config::OPTION_PREFIX . 'license_expired';
	const LICENSE_NOT_ASSOCIATED_WITH_CUSTOMER_OPTION = Mo_License_Config::OPTION_PREFIX . 'lic_not_assoc_cust';
	const IS_TRIAL                        = Mo_License_Config::OPTION_PREFIX . 'tla';

	const DASHBOARD_WIDGET_ID         = Mo_License_Config::OPTION_PREFIX . 'license_details_widget';
	const DASHBOARD_WIDGET_REFRESH_ID = Mo_License_Config::OPTION_PREFIX . 'refresh_expiry';
	const ADMIN_NOTICE_DISMISS_ID     = Mo_License_Config::OPTION_PREFIX . 'license_admin_notice_dismiss';
	const LICENSE_PLAN_OPTION         = 'mo_lp';

	const ADMIN_ERROR_MESSAGE = 'The link you followed has expired. Or your plugin license is invalid.';

	const EXPIRY_IN_30_TO_60_DAYS = 60;
	const EXPIRY_IN_10_TO_30_DAYS = 30;
	const EXPIRY_IN_10_DAYS       = 10;
	const GRACE_PERIOD_STARTED    = 0;
	const GRACE_PERIOD_EXPIRED    = 'GRACE_EXPIRED';
	const TRIAL_PERIOD_STARTED    = 'TRIAL_STARTED';
	const TRIAL_PERIOD_EXPIRED    = 'TRIAL_EXPIRED';
	const MINIORANGE_LOGO_PATH    = 'views/includes/images/miniorange-logo.png';
	const STYLES_FILE_PATH        = 'views/includes/css/license-views-style.min.css';
	const STYLES_ADDONS_PATH      = 'views/includes/css/addons-views-style.min.css';
	const BOOTSTRAP_ADDONS_PATH   = 'views/includes/css/bootstrap/addons-views-bootstrap.min.css';
	const SCRIPTS_FILE_PATH       = 'views/includes/js/license-views-script.js';

	const MESSAGE_LICENSE_KEY_ALREADY_USED                      = 'License Key already used on another instance';
	const MESSAGE_LICENSE_KEY_ATTACHED_TO_DIFFERENT_PLUGIN_TYPE = 'License key is attached with another plugin type';

	const PLUGIN_FILE_PATH = '/wp-admin/includes/plugin.php';
	const FILE_PATH        = '/wp-admin/includes/file.php';

	const ENVIRONMENT_SPECIFIC_HOOKS = array(
		'dashboard_widget' => array(
			'network'    => 'wp_network_dashboard_setup',
			'standalone' => 'wp_dashboard_setup',
		),
		'admin_notice'     => array(
			'network'    => 'network_admin_notices',
			'standalone' => 'admin_notices',
		),
	);


	const LICENSE_VERIFY_VALID_STATUS = 'LICENSE_VALID';
	const LICENSE_VERIFIED_MESSAGE    = 'Your license is verified. You can now setup the plugin.';

	const CUSTOMER_LOGGED_IN_STATUS  = 'CUSTOMER_LOGGED_IN';
	const CUSTOMER_LOGGED_IN_MESSAGE = 'Customer retrieved successfully. You can now proceed to verify your license key.';

	const LICENSE_FREED_STATUS  = 'LICENSE_FREED';
	const LICENSE_FREED_MESSAGE = 'License key freed successfully.';

	const LICENSE_REMOVED_LOCALLY_MESSAGE = 'Account removed locally. The license server could not be reached. You may need to contact support to free the license for use on another site.';

	const LICENSE_SYNCED_STATUS  = 'LICENSE_SYNCED';
	const LICENSE_SYNCED_MESSAGE = 'License details synced successfully.';

	const UPDATE_FRAMEWORK_UTILITY_FILE = 'classes/class-mo-update-framework-utility.php';

	/**
	 * Function to return all constant values of the class.
	 *
	 * @return array
	 */
	public static function get_constants() {
		try {
			$reflection_class = new \ReflectionClass( static::class );
			return $reflection_class->getConstants();
		} catch ( \ReflectionException $e ) {
			return array();
		}
	}
}
