<?php
/**
 * This file contains the class Signature_Not_Found_Exception
 * This exception is thrown when no signature was found in the SAML Response or Assertion.
 *
 * @package miniorange-saml-20-single-sign-on/src/exception
 */

namespace MOSAML\SRC\Exception;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use Exception;

/**
 * This exception indicates that no signature was found in the SAML Response or Assertion.
 */
class Signature_Not_Found_Exception extends Exception {
	/**
	 * Constructor function, which defines the `$code` and `$message` for
	 * the exception, and makes a call to the parent (`Exception`) constructor.
	 *
	 * @param mixed $message this contains the error message.
	 */
	public function __construct( $message ) {
		$message = $message;
		$code    = 03;
		parent::__construct( $message, $code, null );
	}
}
