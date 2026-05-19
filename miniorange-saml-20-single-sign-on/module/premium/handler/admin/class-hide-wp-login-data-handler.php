<?php
/**
 * Hide WP Login Data Handler - Premium Module
 *
 * Extends the standard hide-wp-login data handler to provide premium module functionality.
 *
 * @package miniorange-saml-20-single-sign-on
 * @subpackage Module\Premium\Handler\Admin
 */

namespace MOSAML\Module\Premium\Handler\Admin;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\Module\Standard\Handler\Admin\Hide_WP_Login_Data_Handler as Standard_Hide_WP_Login_Data_Handler;
use MOSAML\SRC\Interfaces\Form_Data_Handler_Interface;

/**
 * Hide WP Login Data Handler.
 */
class Hide_WP_Login_Data_Handler extends Standard_Hide_WP_Login_Data_Handler implements Form_Data_Handler_Interface {}
