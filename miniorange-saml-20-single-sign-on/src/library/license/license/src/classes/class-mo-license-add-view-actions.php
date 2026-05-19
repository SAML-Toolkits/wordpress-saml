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

use MOSAML\LicenseLibrary\Handlers\Mo_License_Add_View_Handler;
use MOSAML\LicenseLibrary\Mo_License_Config;
use MOSAML\LicenseLibrary\Utils\Mo_License_Actions_Utility;
use MOSAML\LicenseLibrary\Utils\Mo_License_Service_Utility;

/**
 * Class Mo_License_Add_View_Actions adds all actions related to the
 * license framework views.
 */
class Mo_License_Add_View_Actions {

	/**
	 * Mo_License_Actions_Handler object.
	 *
	 * @var Mo_License_Add_View_Handler
	 */
	private $license_add_view_handler;

	/**
	 * Instantiates the class objects required for self functioning.
	 *
	 * @param Mo_License_Add_View_Handler $license_add_view_handler View Actions Callback Object.
	 */
	public function __construct( $license_add_view_handler ) {

		$this->license_add_view_handler = $license_add_view_handler;
		$this->add_license_views();
	}

	/**
	 * Adds all hooks to initiate actions related to the views of
	 * the license framework.
	 *
	 * @return void
	 */
	public function add_license_views() {

		add_action( 'admin_enqueue_scripts', array( $this->license_add_view_handler, 'add_plugin_license_scripts' ) );
		add_action( Mo_License_Actions_Utility::get_current_environment_hook_name( 'admin_notice' ), array( $this->license_add_view_handler, 'add_admin_license_notice' ) );
		if ( 'FAILED' === Mo_License_Service_Utility::mo_decrypt_data( Mo_License_Dao::mo_get_option( Mo_License_Constants::DOMAIN_CHECK_FAILED_OPTION ) ) ) {
			add_action( Mo_License_Actions_Utility::get_current_environment_hook_name( 'admin_notice' ), array( $this->license_add_view_handler, 'add_domain_check_notice' ) );
		}
		if ( Mo_License_Config::ADD_DASHBOARD_WIDGET ) {
			add_action( Mo_License_Actions_Utility::get_current_environment_hook_name( 'dashboard_widget' ), array( $this->license_add_view_handler, 'add_dashboard_license_widget' ) );
		}
	}
}