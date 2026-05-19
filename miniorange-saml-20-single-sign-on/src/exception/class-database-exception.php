<?php
/**
 * This file contains the class Database_Exception
 * This exception is thrown when any database operation fails.
 *
 * @package miniorange-saml-20-single-sign-on/src/exception
 */

namespace MOSAML\SRC\Exception;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use Exception;

/**
 * Database Exception Class.
 */
class Database_Exception extends Exception {

	/**
	 * Constructor for Database_Exception.
	 *
	 * @param string $message  The exception message.
	 */
	public function __construct( string $message = '' ) {
		$code = 041;
		parent::__construct( $message, $code, null );
	}
}
