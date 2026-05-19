<?php
/**
 * This file contains the class IDP_Status_Inactive_Exception
 * This exception is thrown when the IDP status is inactive but the user tries to log in to the site.
 *
 * @package miniorange-saml-20-single-sign-on/src/exception
 */

namespace MOSAML\SRC\Exception;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use Exception;

/**
 * This exception indicates that the IDP status is inactive but the user tries to log in to the site.
 */
class IDP_Status_Inactive_Exception extends Exception {

	/**
	 * Constructor function, which defines the `$code` and `$message` for
	 * the exception, and makes a call to the parent (`Exception`) constructor.
	 *
	 * @param string $message The exception message.
	 */
	public function __construct( $message ) {
		$message = $message;
		$code    = 23;
		parent::__construct( $message, $code, null );
	}
}
