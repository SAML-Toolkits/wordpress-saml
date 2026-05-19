<?php
/**
 * Premium Force Authentication Data Handler.
 *
 * @package miniorange-saml-20-single-sign-on/module/premium/handler/admin
 */

namespace MOSAML\Module\Premium\Handler\Admin;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\Module\Standard\Handler\Admin\Force_Authentication_Data_Handler as Standard_Force_Authentication_Data_Handler;
use MOSAML\SRC\Interfaces\Form_Data_Handler_Interface;

/**
 * Premium Force Authentication Data Handler.
 * Extends Standard implementation and can add premium-specific features.
 */
class Force_Authentication_Data_Handler extends Standard_Force_Authentication_Data_Handler implements Form_Data_Handler_Interface {}
