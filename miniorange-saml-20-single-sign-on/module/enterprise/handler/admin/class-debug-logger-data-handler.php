<?php
/**
 * Debug Logger Data Handler - Enterprise Module
 *
 * @package miniorange-saml-20-single-sign-on/module/enterprise/handler/admin
 */

namespace MOSAML\Module\Enterprise\Handler\Admin;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\SRC\Interfaces\Form_Data_Handler_Interface;
use MOSAML\Module\Premium\Handler\Admin\Debug_Logger_Data_Handler as Premium_Debug_Logger_Data_Handler;

/**
 * Debug Logger Data Handler - Enterprise Module
 */
class Debug_Logger_Data_Handler extends Premium_Debug_Logger_Data_Handler implements Form_Data_Handler_Interface {}
