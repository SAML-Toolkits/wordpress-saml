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

use MOSAML\LicenseLibrary\Handlers\Mo_License_Actions_Handler;
use MOSAML\LicenseLibrary\Mo_License_Config;
use MOSAML\LicenseLibrary\Utils\Mo_License_Actions_Utility;

/**
 * Class Mo_License_Actions adds all actions related to the license framework.
 */
class Mo_License_Actions {

	/**
	 * Mo_License_Actions_Handler object.
	 *
	 * @var Mo_License_Actions_Handler
	 */
	private $license_action_handler;

	/**
	 * Instantiates the class objects required for self functioning.
	 *
	 * @param Mo_License_Actions_Handler $license_action_handler Actions Callback Object.
	 */
	public function __construct( $license_action_handler ) {

		$this->license_action_handler = $license_action_handler;
		$this->add_license_actions();
	}

	/**
	 * Adds all hooks to initiate actions related to the license framework.
	 *
	 * @return void
	 */
	public function add_license_actions() {

		add_action( 'init', array( $this->license_action_handler, 'run_license_cron' ) );
		add_action( 'init', array( $this->license_action_handler, 'run_domain_check_cron' ) );

		add_action( 'admin_init', array( $this->license_action_handler, 'dismiss_admin_license_notice' ) );
		add_action( 'admin_init', array( $this->license_action_handler, 'refresh_admin_widget_expiry' ) );
	}
}