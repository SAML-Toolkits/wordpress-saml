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
 * Exception to depict that license is already in used on another site.
 */
class Mo_License_Already_Used_License_Key_Exception extends \Exception {

	const CODE    = 'ALREADY_USED_LICENSE_KEY';
	const MESSAGE = 'The license key is already in use on another site. Please contact miniOrange support for assistance.';

	/**
	 * Initializes the Exception with the Exception Message.
	 */
	public function __construct() {
		parent::__construct( self::CODE );
	}
}