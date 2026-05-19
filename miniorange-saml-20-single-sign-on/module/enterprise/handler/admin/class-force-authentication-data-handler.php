<?php
/**
 * Enterprise Force Authentication Data Handler.
 *
 * @package miniorange-saml-20-single-sign-on/module/enterprise/handler/admin
 */

namespace MOSAML\Module\Enterprise\Handler\Admin;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\Module\Premium\Handler\Admin\Force_Authentication_Data_Handler as Premium_Force_Authentication_Data_Handler;
use MOSAML\SRC\Interfaces\Form_Data_Handler_Interface;

/**
 * Enterprise Force Authentication Data Handler.
 * Extends Premium implementation and can add enterprise-specific features.
 */
class Force_Authentication_Data_Handler extends Premium_Force_Authentication_Data_Handler implements Form_Data_Handler_Interface {}
