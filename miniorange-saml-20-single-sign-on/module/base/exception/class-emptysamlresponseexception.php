<?php
/**
 * Empty SAML response exception.
 *
 * @package miniorange-saml-20-single-sign-on
 */

namespace MOSAML\Module\Base\Exception;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Exception for empty SAML response.
 */
class EmptySamlResponseException extends \RuntimeException {}
