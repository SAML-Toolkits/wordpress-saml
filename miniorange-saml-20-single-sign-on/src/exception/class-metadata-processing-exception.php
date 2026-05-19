<?php
/**
 * This file contains the class Metadata_Processing_Exception
 * This exception is thrown when there are errors during metadata processing operations.
 *
 * @package miniorange-saml-20-single-sign-on/src/exception
 */

namespace MOSAML\SRC\Exception;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use Exception;

/**
 * This exception indicates that there was an error during metadata processing.
 */
class Metadata_Processing_Exception extends Exception {

	/**
	 * Constructor function, which defines the `$code` and `$message` for
	 * the exception, and makes a call to the parent (`Exception`) constructor.
	 *
	 * @param string $message The exception message.
	 * @param string $operation The operation that failed (e.g., 'file_upload', 'url_fetch', 'parsing').
	 */
	public function __construct( $message, $operation = '' ) {
		$formatted_message = $operation ? sprintf( '[%s] %s', $operation, $message ) : $message;
		$code              = 31;
		parent::__construct( $formatted_message, $code, null );
	}
}
