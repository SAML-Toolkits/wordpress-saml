<?php
/**
 * User restriction handler (enterprise module).
 *
 * @package miniorange-saml-20-single-sign-on
 */

namespace MOSAML\Module\Enterprise\Handler\Config;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\Module\Premium\Handler\User_Restriction_Handler as Premium_User_Restriction_Handler;
use MOSAML\Traits\Instance;

/**
 * User Restriction Handler.
 *
 * @package MOSAML\Module\Enterprise\Handler
 */
class User_Restriction_Handler extends Premium_User_Restriction_Handler {
	use Instance;
}
