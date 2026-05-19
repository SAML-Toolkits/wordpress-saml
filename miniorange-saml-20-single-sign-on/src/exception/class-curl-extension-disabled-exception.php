<?php
/**
 * This file contains the class CURL_Extension_Disabled_Exception
 * This exception is thrown when PHP CURL extension is disabled.
 *
 * @package miniorange-saml-20-single-sign-on/src/exception
 */

namespace MOSAML\SRC\Exception;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use Exception;

/**
 * This exception indicates that the PHP CURL extension is disabled.
 */
class CURL_Extension_Disabled_Exception extends Exception {

	/**
	 * Constructor function, which defines the `$code` and `$message` for
	 * the exception, and makes a call to the parent (`Exception`) constructor.
	 *
	 * @param mixed $message this contains the error message.
	 */
	public function __construct( $message ) {
		$message = $message;
		$code    = '32';
		parent::__construct( $message, $code, null );
	}
}
