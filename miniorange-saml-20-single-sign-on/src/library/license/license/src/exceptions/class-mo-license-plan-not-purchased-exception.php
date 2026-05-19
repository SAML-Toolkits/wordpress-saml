<?php
/**
 * This file is part of miniOrange WP plugin.
 *
 * @package    miniOrange
 * @author     miniOrange Security Software Pvt. Ltd.
 */

namespace MOSAML\LicenseLibrary\Exceptions;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Exception to depict that the customer is not upgraded to this license plan.
 */
class Mo_License_Plan_Not_Purchased_Exception extends \Exception {

	const CODE    = 'LICENSE_PLAN_NOT_PURCHASED';
	const MESSAGE = 'The license plan you are trying to access has not been purchased. Please upgrade your plan to activate this plugin.';

	/**
	 * Initializes the Exception with the Exception Message.
	 */
	public function __construct() {
		parent::__construct( self::CODE );
	}
}
