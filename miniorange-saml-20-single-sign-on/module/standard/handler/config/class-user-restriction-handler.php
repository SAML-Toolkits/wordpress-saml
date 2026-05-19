<?php
/**
 * User restriction handler (standard module).
 *
 * @package miniorange-saml-20-single-sign-on
 */

namespace MOSAML\Module\Standard\Handler\Config;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\Module\Base\Handler\Config\User_Restriction_Handler as Base_User_Restriction_Handler;
use MOSAML\Traits\Instance;

/**
 * User Restriction Handler.
 *
 * @package MOSAML\Module\Standard\Handler
 */
class User_Restriction_Handler extends Base_User_Restriction_Handler {
	use Instance;
}
