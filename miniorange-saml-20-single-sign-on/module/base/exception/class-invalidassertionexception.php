<?php
/**
 * Invalid Assertion Exception
 *
 * @package MOSAML\Module\Base\Exception
 */

namespace MOSAML\Module\Base\Exception;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Exception for invalid SAML assertions
 */
class InvalidAssertionException extends \RuntimeException {}
