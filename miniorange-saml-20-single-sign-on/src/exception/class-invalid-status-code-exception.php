<?php
/**
 * This file contains the class Invalid_Status_Code_Exception
 * This exception is thrown when IDP returns a status code other than SUCCESS.
 *
 * @package miniorange-saml-20-single-sign-on/src/exception
 */

namespace MOSAML\SRC\Exception;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use Exception;

/**
 * This exception indicates that the IDP returned a status code other than SUCCESS.
 */
class Invalid_Status_Code_Exception extends Exception {
	/**
	 * Constructor function, which defines the `$code` and `$message` for
	 * the exception, and makes a call to the parent (`Exception`) constructor.
	 *
	 * @param mixed $message this contains the error message.
	 */
	public function __construct( $message ) {
		$message = $message;
		$code    = 06;
		parent::__construct( $message, $code, null );
	}
}
