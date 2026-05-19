<?php
/**
 * This file contains the class SP_Clock_Ahead_Of_IDP_Clock_Exception
 * This exception is thrown when your SP clock is ahead the IDP clock.
 *
 * @package miniorange-saml-20-single-sign-on/src/exception
 */

namespace MOSAML\SRC\Exception;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use Exception;

/**
 * This exception indicates that your SP clock is ahead the IDP clock.
 */
class SP_Clock_Ahead_Of_IDP_Clock_Exception extends Exception {
	/**
	 * Constructor function, which defines the `$code` and `$message` for
	 * the exception, and makes a call to the parent (`Exception`) constructor.
	 *
	 * @param mixed $message this contains the error message.
	 */
	public function __construct( $message ) {
		$message = $message;
		$code    = 8;
		parent::__construct( $message, $code, null );
	}
}
