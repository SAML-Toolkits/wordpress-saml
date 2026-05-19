<?php
/**
 * Debug Logger Data Handler - Premium Module
 *
 * @package miniorange-saml-20-single-sign-on/module/premium/handler/admin
 */

namespace MOSAML\Module\Premium\Handler\Admin;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\SRC\Interfaces\Form_Data_Handler_Interface;
use MOSAML\Module\Standard\Handler\Admin\Debug_Logger_Data_Handler as Standard_Debug_Logger_Data_Handler;

/**
 * Debug Logger Data Handler - Premium Module
 */
class Debug_Logger_Data_Handler extends Standard_Debug_Logger_Data_Handler implements Form_Data_Handler_Interface {}
