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
 * Exception to depict that the license key entered or the customer logged in is invalid.
 */
class Mo_License_Invalid_License_Key_Exception extends \Exception {

	const CODE    = 'INVALID_LICENSE_KEY';
	const MESSAGE = 'The license key entered is invalid. Please check the license key and try again.';
	/**
	 * Initializes the Exception with the Exception Message.
	 */
	public function __construct() {
		parent::__construct( self::CODE );
	}
}