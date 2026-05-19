<?php
/**
 * This file contains the class OpenSSL_Extension_Disabled_Exception
 * This exception is thrown when PHP OpenSSL extension is disabled.
 *
 * @package    miniOrange
 * @author     miniOrange Security Software Pvt. Ltd.
 */

namespace MOSAML\LicenseLibrary\Exceptions;

use Exception;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * This exception indicates that the PHP OpenSSL extension is disabled.
 */
class OpenSSL_Extension_Disabled_Exception extends Exception {

	/**
	 * Constructor function, which defines the `$code` and `$message` for
	 * the exception, and makes a call to the parent (`Exception`) constructor.
	 *
	 * @param mixed $message this contains the error message.
	 */
	public function __construct( $message ) {
		$message = $message;
		$code    = '20';
		parent::__construct( $message, $code, null );
	}
}