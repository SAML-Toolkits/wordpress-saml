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
 * Exception to depict that the there has been an unknown error while processing the
 * License Expiry Date found in the database.
 */
class Mo_License_Unknown_Error_Exception extends \Exception {

	const CODE    = 'UNKNOWN_ERROR';
	const MESSAGE = 'An unknown error occurred.';


	/**
	 * Initializes the Exception with the Exception Message.
	 */
	public function __construct() {
		parent::__construct( self::MESSAGE );
	}
}
