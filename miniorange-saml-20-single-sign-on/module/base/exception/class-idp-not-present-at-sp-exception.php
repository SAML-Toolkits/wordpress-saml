<?php
/**
 * Exception for IDP not present at SP.
 *
 * @package miniorange-saml-20-single-sign-on/exception
 */

namespace MOSAML\Module\Base\Exception;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use Exception;


/**
 * Exception for IDP not present at SP.
 */
class IDP_Not_Present_At_SP_Exception extends Exception {

	/**
	 * Constructor function, which defines the `$code` and `$message` for
	 * the exception, and makes a call to the parent (`Exception`) constructor.
	 *
	 * @param mixed $message this contains the error message.
	 */
	public function __construct( $message ) {
		$message = $message;
		$code    = '36';
		parent::__construct( $message, $code, null );
	}
}
