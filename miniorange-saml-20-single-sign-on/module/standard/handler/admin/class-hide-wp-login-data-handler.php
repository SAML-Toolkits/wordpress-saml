<?php
/**
 * Hide WP Login Data Handler - Standard Module
 *
 * Extends the base hide-wp-login data handler to provide standard module functionality.
 *
 * PHP Compatibility: 5.6+
 *
 * @package miniorange-saml-20-single-sign-on
 * @subpackage Module\Standard\Handler\Admin
 */

namespace MOSAML\Module\Standard\Handler\Admin;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\Module\Base\Handler\Admin\Hide_WP_Login_Data_Handler as Base_Hide_WP_Login_Data_Handler;
use MOSAML\SRC\Interfaces\Form_Data_Handler_Interface;

/**
 * Hide WP Login Data Handler.
 */
class Hide_WP_Login_Data_Handler extends Base_Hide_WP_Login_Data_Handler implements Form_Data_Handler_Interface {}
