<?php
/**
 * Debug Logger Data Handler - Standard Module
 *
 * @package miniorange-saml-20-single-sign-on/module/standard/handler/admin
 */

namespace MOSAML\Module\Standard\Handler\Admin;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\SRC\Interfaces\Form_Data_Handler_Interface;
use MOSAML\Module\Base\Handler\Admin\Debug_Logger_Data_Handler as Base_Debug_Logger_Data_Handler;

/**
 * Debug Logger Data Handler.
 */
class Debug_Logger_Data_Handler extends Base_Debug_Logger_Data_Handler implements Form_Data_Handler_Interface {}
