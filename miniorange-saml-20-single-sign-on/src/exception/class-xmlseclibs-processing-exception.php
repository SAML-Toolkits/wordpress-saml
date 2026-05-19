<?php
/**
 * This file contains the class XMLSecLibs_Processing_Exception
 * This exception is thrown when we are unable to process XML with XMLSecLibs.
 *
 * @package miniorange-saml-20-single-sign-on/src/exception
 */

namespace MOSAML\SRC\Exception;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use Exception;

/**
 * This exception indicates that we are unable to process XML with XMLSecLibs.
 */
class XMLSecLibs_Processing_Exception extends Exception {

	/**
	 * Constructor function, which defines the `$code` and `$message` for
	 * the exception, and makes a call to the parent (`Exception`) constructor.
	 *
	 * @param string $message The exception message.
	 */
	public function __construct( $message ) {
		$message = $message;
		$code    = 28;
		parent::__construct( $message, $code, null );
	}
}
