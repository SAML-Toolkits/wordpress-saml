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

use MOSAML\LicenseLibrary\Classes\Mo_License_Constants;
use MOSAML\LicenseLibrary\Classes\Mo_License_Library;
use MOSAML\LicenseLibrary\Mo_License_Config;
use MOSAML\LicenseLibrary\Mo_License_Service;
use MOSAML\LicenseLibrary\Views\Mo_License_Notice_Views;

/**
 * Class Mo_License_Add_View_Handler contains all callback functions for the
 * license framework view related hooks.
 */
class Mo_License_Add_View_Handler {

	/**
	 * Mo_License_Notice_Views Object.
	 *
	 * @var Mo_License_Notice_Views
	 */
	private $license_views;

	/**
	 * Instantiates the class objects required for self functioning.
	 *
	 * @param Mo_License_Notice_Views $license_views Mo_License_Notice_Views Object.
	 */
	public function __construct( $license_views ) {
		$this->license_views = $license_views;
	}

	/**
	 * Prints a warning admin notice when remaining days for license expiry is less than 60 days.
	 *
	 * @return void
	 */
	public function add_admin_license_notice() {

		if ( Mo_License_Service::is_customer_license_verified() && current_user_can( 'manage_options' ) ) {

			$license_notice_escaped = $this->license_views->get_license_notice();

            //PHPCS:ignore -- WordPress.Security.EscapeOutput.OutputNotEscaped -- Notice escaped while creation.
            echo $license_notice_escaped;
		}
	}

	/**
	 * Prints a warning admin notice when domain check has failed.
	 *
	 * @return void
	 */
	public function add_domain_check_notice() {
		if ( Mo_License_Service::is_customer_license_verified() && current_user_can( 'manage_options' ) ) {

			$domain_check_notice_escaped = $this->license_views->get_domain_check_failed_notice();

            //PHPCS:ignore -- WordPress.Security.EscapeOutput.OutputNotEscaped -- Notice escaped while creation.
            echo $domain_check_notice_escaped;
		}
	}

	/**
	 * Adds a WP dashboard widget to display the plugin's license information.
	 *
	 * @return void
	 */
	public function add_dashboard_license_widget() {

		if ( Mo_License_Service::is_customer_license_verified() && current_user_can( 'manage_options' ) ) {

			global $wp_meta_boxes;

			wp_add_dashboard_widget(
				Mo_License_Constants::DASHBOARD_WIDGET_ID,
				Mo_License_Config::PLUGIN_NAME,
				array( $this->license_views, 'display_dashboard_widget' )
			);

			$dashboard_name = 'dashboard';
			if ( 'network' === Mo_License_Library::$environment_type ) {
				$dashboard_name = 'dashboard-network';
			}

			$dashboard = $wp_meta_boxes[ $dashboard_name ]['normal']['core'];

			$mo_license_widget = array( Mo_License_Constants::DASHBOARD_WIDGET_ID => $dashboard[ Mo_License_Constants::DASHBOARD_WIDGET_ID ] );
			unset( $dashboard[ Mo_License_Constants::DASHBOARD_WIDGET_ID ] );

			$dashboard        = ! empty( $dashboard ) ? $dashboard : array();
			$sorted_dashboard = array_merge( $mo_license_widget, $dashboard );
            //PHPCS:ignore -- WordPress.WP.GlobalVariablesOverride.Prohibited -- Required to add widget to the dashboard top
            $wp_meta_boxes[ $dashboard_name ]['normal']['core'] = $sorted_dashboard;
		}
	}

	/**
	 * Adds styles and scripts for license framework.
	 *
	 * @return void
	 */
	public function add_plugin_license_scripts() {
		wp_enqueue_style( Mo_License_Config::OPTION_PREFIX . 'license_view_style', Mo_License_Service::get_license_library_path() . Mo_License_Constants::STYLES_FILE_PATH, array(), Mo_License_Constants::VERSION );
		wp_enqueue_style( 'mo_addon_view_style', MO_LICENSE_LIBRARY_PATH . Mo_License_Constants::STYLES_ADDONS_PATH, array(), Mo_License_Constants::VERSION );
		wp_enqueue_style( 'mo_addon_view_bootstrap_style', MO_LICENSE_LIBRARY_PATH . Mo_License_Constants::BOOTSTRAP_ADDONS_PATH, array(), Mo_License_Constants::VERSION );

		wp_enqueue_script( 'mo_license_views_script', MO_LICENSE_LIBRARY_PATH . Mo_License_Constants::SCRIPTS_FILE_PATH, array( 'jquery' ), Mo_License_Constants::VERSION, true );

		wp_localize_script(
			'mo_license_views_script',
			'moAddonsData',
			array(
				'nonce' => wp_create_nonce( 'mo_install_addon' ),
			)
		);
	}
}
