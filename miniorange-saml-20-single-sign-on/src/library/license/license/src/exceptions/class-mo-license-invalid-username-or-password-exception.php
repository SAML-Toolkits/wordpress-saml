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
 * Exception to depict that the username and password entered is invalid.
 */
class Mo_License_Invalid_Username_Or_Password_Exception extends \Exception {

	const CODE    = 'INVALID_EMAIL_OR_PASSWORD';
	const MESSAGE = 'The username or password entered is invalid. Please check the username and password and try again.';

	/**
	 * Initializes the Exception with the Exception Message.
	 */
	public function __construct() {
		parent::__construct( self::MESSAGE );
	}
}