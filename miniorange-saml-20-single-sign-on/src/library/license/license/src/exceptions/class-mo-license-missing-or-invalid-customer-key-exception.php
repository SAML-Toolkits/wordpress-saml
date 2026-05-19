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
 * Exception to depict that the Customer's miniOrange Account Customer Key
 * is not found in the database.
 */
class Mo_License_Missing_Or_Invalid_Customer_Key_Exception extends \Exception {

	const CODE    = 'MISSING_OR_INVALID_CUSTOMER_KEY';
	const MESSAGE = 'The customer key is missing or invalid. Please log into the plugin to proceed.';

	/**
	 * Initializes the Exception with the Exception Message.
	 */
	public function __construct() {
		parent::__construct( self::MESSAGE );
	}
}