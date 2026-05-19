<?php
/**
 * Metadata Upload Exception
 *
 * @package miniorange-saml-20-single-sign-on/src/exception
 */

namespace MOSAML\SRC\Exception;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use Exception;

/**
 * Exception for metadata upload failures
 */
class Metadata_Upload_Exception extends Exception {

	/**
	 * Constructor function, which defines the `$code` and `$message` for
	 * the exception, and makes a call to the parent (`Exception`) constructor.
	 *
	 * @param string $message The error message.
	 * @param int    $code    error code. Default 0.
	 */
	public function __construct( $message, $code = 0 ) {
		$message = $message;
		parent::__construct( $message, $code, null );
	}
}
