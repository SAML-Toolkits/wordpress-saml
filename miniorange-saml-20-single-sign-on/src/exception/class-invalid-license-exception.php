<?php
/**
 * This file contains the class Invalid_License_Exception
 * This exception is thrown when the plugin license is invalid.
 *
 * @package miniorange-saml-20-single-sign-on/src/exception
 */

namespace MOSAML\SRC\Exception;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use Exception;

/**
 * This exception indicates that the plugin license is invalid.
 */
class Invalid_License_Exception extends Exception {

	/**
	 * Constructor function, which defines the `$code` and `$message` for
	 * the exception, and makes a call to the parent (`Exception`) constructor.
	 *
	 * @param string $message The exception message.
	 */
	public function __construct( $message ) {
		$message = $message;
		$code    = 29;
		parent::__construct( $message, $code, null );
	}
}
