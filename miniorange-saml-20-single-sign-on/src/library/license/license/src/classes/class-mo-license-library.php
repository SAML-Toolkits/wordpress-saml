<?php
/**
 * This file contains the License Library Class which is implemented
 * in miniOrange WP plugins for handling licensing.
 *
 * @version 1.0.8
 * @package miniOrange
 * @author  miniOrange Security Software Pvt. Ltd.
 */

namespace MOSAML\LicenseLibrary\Classes;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\LicenseLibrary\Handlers\Mo_License_Actions_Handler;
use MOSAML\LicenseLibrary\Handlers\Mo_License_Add_View_Handler;
use MOSAML\LicenseLibrary\Handlers\Mo_License_Install_Addon_Handler;
use MOSAML\LicenseLibrary\Utils\Mo_License_Actions_Utility;
use MOSAML\LicenseLibrary\Views\Mo_License_Notice_Views;
use MOSAML\LicenseLibrary\Mo_License_Service;

/**
 * Contains licensing framework logic and functionality.
 */
class Mo_License_Library {

	/**
	 * Stores Expiry Date value.
	 *
	 * @var string
	 */
	private $license_expiry_date;

	/**
	 * Stores the type of environment.
	 *
	 * @var string
	 */
	public static $environment_type;

	/**
	 * Mo_License_Actions Object.
	 *
	 * @var Mo_License_Actions
	 */
	private $license_actions;

	/**
	 * Mo_License_Actions_Handler Object.
	 *
	 * @var Mo_License_Actions_Handler
	 */
	private $license_actions_handler;

	/**
	 * Mo_License_Notice_Views Object.
	 *
	 * @var Mo_License_Notice_Views
	 */
	private $license_views;

	/**
	 * Mo_License_Add_View_Handler Object.
	 *
	 * @var Mo_License_Add_View_Handler
	 */
	private $license_add_view_handler;

	/**
	 * Mo_License_Add_View_Actions Object.
	 *
	 * @var Mo_License_Add_View_Actions
	 */
	private $license_add_view_actions;

	/**
	 * Mo_License Object for addon functionality.
	 *
	 * @var Mo_License_Install_Addon_Handler
	 */
	private $get_addon;

	/**
	 * Initializes all required objects and adds the required actions for the License Library
	 * if the customer is logged into the plugin.
	 */
	public function __construct() {

		$this->set_environment_type();

		if ( Mo_License_Service::is_customer_license_verified() ) {
			$this->set_license_expiry();
			$this->add_license_actions();
		}

		$this->add_license_views();
		Mo_License_Service::add_addons_license_filters();
	}

	/**
	 * Initializes required objects of the License Library.
	 *
	 * @return void
	 */
	private function add_license_actions() {
		$this->license_actions_handler = new Mo_License_Actions_Handler( $this->license_expiry_date );
		$this->license_actions         = new Mo_License_Actions( $this->license_actions_handler );
		$this->get_addon               = new Mo_License_Install_Addon_Handler();
	}

	/**
	 * Adds license admin notice and dashboard widget.
	 *
	 * @return void
	 */
	private function add_license_views() {

		$this->license_views            = new Mo_License_Notice_Views();
		$this->license_add_view_handler = new Mo_License_Add_View_Handler( $this->license_views );
		$this->license_add_view_actions = new Mo_License_Add_View_Actions( $this->license_add_view_handler );
	}

	/**
	 * Sets license expiry date.
	 *
	 * @return void
	 */
	private function set_license_expiry() {
		$this->license_expiry_date = Mo_License_Service::get_expiry_date();
	}

	/**
	 * Sets the type of environment on which the library is activated.
	 */
	private function set_environment_type() {
		self::$environment_type = Mo_License_Actions_Utility::get_environment_type();
	}
}
