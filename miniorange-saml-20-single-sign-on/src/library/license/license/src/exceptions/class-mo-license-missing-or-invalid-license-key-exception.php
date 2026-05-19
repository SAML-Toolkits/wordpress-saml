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
 * Exception to depict that the entered Customer's License Key is not in a valid format or missing.
 */
class Mo_License_Missing_Or_Invalid_License_Key_Exception extends \Exception {

	const MESSAGE = 'MISSING_OR_INVALID_LICENSE_KEY';

	/**
	 * Initializes the Exception with the Exception Message.
	 */
	public function __construct() {
		parent::__construct( self::MESSAGE );
	}
}