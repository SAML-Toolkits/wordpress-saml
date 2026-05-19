<?php
/**
 * Invalid SAML Response Exception
 *
 * @package MOSAML\Module\Base\Exception
 */

namespace MOSAML\Module\Base\Exception;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Exception for invalid SAML response
 */
class InvalidSamlResponseException extends \RuntimeException {}
