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
 * Exception to depict that Plugin's License Grace Period has expired.
 */
class Mo_License_Grace_Expired_Exception extends \Exception {

	const MESSAGE = 'LICENSE_GRACE_EXPIRED';

	/**
	 * Initializes the Exception with the Exception Message.
	 */
	public function __construct() {
		parent::__construct( self::MESSAGE );
	}
}
