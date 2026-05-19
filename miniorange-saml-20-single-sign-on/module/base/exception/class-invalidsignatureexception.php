<?php
/**
 * Invalid Signature Exception
 *
 * @package MOSAML\Module\Base\Exception
 */

namespace MOSAML\Module\Base\Exception;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Exception for invalid SAML signatures
 */
class InvalidSignatureException extends \RuntimeException {}
