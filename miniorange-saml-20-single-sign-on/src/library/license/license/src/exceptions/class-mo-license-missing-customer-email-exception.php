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
 * Exception to depict that the Customer's miniOrange Account Email Address
 * is not found in the database.
 */
class Mo_License_Missing_Customer_Email_Exception extends \Exception {

	const CODE    = 'MISSING_CUSTOMER_EMAIL';
	const MESSAGE = 'The customer email address is missing. Please log into the plugin with a valid email address to proceed.';

	/**
	 * Initializes the Exception with the Exception Message.
	 */
	public function __construct() {
		parent::__construct( self::MESSAGE );
	}
}