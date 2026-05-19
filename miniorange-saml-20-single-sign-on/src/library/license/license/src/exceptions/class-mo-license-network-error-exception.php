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
 * Exception to depict that the device is not connected to stable internet.
 */
class Mo_License_Network_Error_Exception extends \Exception {

	const CODE    = 'NETWORK_ERROR';
	const MESSAGE = 'Network error occurred. Please check your internet connection and try again.';

	/**
	 * Initializes the Exception with the Exception Message.
	 */
	public function __construct() {
		parent::__construct( self::MESSAGE );
	}
}