<?php
/**
 * This file contains the class Mo_SAML_DOM_Extension_Disabled_Exception
 * This exception is thrown when PHP DOM extension is disabled.
 *
 * @package miniorange-saml-20-single-sign-on/exception
 */

namespace MOSAML\Module\Base\Exception;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use Exception;

/**
 * This exception indicates that the PHP DOM extension is disabled.
 */
class DOM_Extension_Disabled_Exception extends Exception {
	/**
	 * Constructor function, which defines the `$code` and `$message` for
	 * the exception, and makes a call to the parent (`Exception`) constructor.
	 *
	 * @param mixed $message this contains the error message.
	 */
	public function __construct( $message ) {
		$message = $message;
		$code    = '15';
		parent::__construct( $message, $code, null );
	}
}
