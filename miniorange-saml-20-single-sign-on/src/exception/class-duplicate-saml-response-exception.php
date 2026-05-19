<?php
/**
 * This file contains the class Duplicate_SAML_Response_Exception
 * This exception is thrown when the plugin detects a duplicate saml response
 *
 * @package miniorange-saml-20-single-sign-on/src/exception
 */

namespace MOSAML\SRC\Exception;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use Exception;

/**
 * This exception indicates that the plugin detected a duplicate saml response.
 */
class Duplicate_SAML_Response_Exception extends Exception {

	/**
	 * Constructor function, which defines the `$code` and `$message` for
	 * the exception, and makes a call to the parent (`Exception`) constructor.
	 *
	 * @param string $message The exception message.
	 */
	public function __construct( $message ) {
		$message = $message;
		$code    = 16;
		parent::__construct( $message, $code, null );
	}
}
