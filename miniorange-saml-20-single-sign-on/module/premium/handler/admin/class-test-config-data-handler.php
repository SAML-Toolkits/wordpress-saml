<?php
/**
 * Test Config Data Handler - Premium Module
 *
 * Extends the base test config data handler to provide premium module functionality.
 *
 * @package miniorange-saml-20-single-sign-on
 * @subpackage Module\Premium\Handler\Admin
 */

namespace MOSAML\Module\Premium\Handler\Admin;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\Module\Standard\Handler\Admin\Test_Config_Data_Handler as Standard_Test_Config_Data_Handler;
use MOSAML\SRC\Interfaces\Form_Data_Handler_Interface;

/**
 * Test Config Data Handler.
 */
class Test_Config_Data_Handler extends Standard_Test_Config_Data_Handler implements Form_Data_Handler_Interface {}
