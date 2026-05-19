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
 * Exception to depict that Plugin's Expiry Date is not in the correct format.
 */
class Mo_License_Invalid_Expiry_Date_Exception extends \Exception {

	const MESSAGE = 'MISSING_OR_INVALID_EXPIRY_DATE';

	/**
	 * Initializes the Exception with the Exception Message.
	 */
	public function __construct() {
		parent::__construct( self::MESSAGE );
	}
}