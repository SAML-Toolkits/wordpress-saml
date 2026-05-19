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
 * Exception to depict that the License Key used to login into the plugin
 * is not found in the database.
 */
class Mo_License_Missing_License_Key_Exception extends \Exception {

	const CODE    = 'MISSING_LICENSE_KEY';
	const MESSAGE = 'License key is missing. Please enter a valid license key to proceed.';

	/**
	 * Initializes the Exception with the Exception Message.
	 */
	public function __construct() {
		parent::__construct( self::MESSAGE );
	}
}