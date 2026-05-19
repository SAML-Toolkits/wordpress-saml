<?php
/**
 * This file contains the class Invalid_Entity_ID_Exception
 * This exception is thrown when you have configured wrong IDP Entity ID in the plugin.
 *
 * @package miniorange-saml-20-single-sign-on/src/exception
 */

namespace MOSAML\SRC\Exception;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use Exception;

/**
 * This exception indicates that you have configured wrong IDP Entity ID in the plugin.
 */
class Invalid_Entity_ID_Exception extends Exception {
	/**
	 * Constructor function, which defines the `$code` and `$message` for
	 * the exception, and makes a call to the parent (`Exception`) constructor.
	 *
	 * @param mixed $message this contains the error message.
	 */
	public function __construct( $message ) {
		$message = $message;
		$code    = 10;
		parent::__construct( $message, $code, null );
	}
}
