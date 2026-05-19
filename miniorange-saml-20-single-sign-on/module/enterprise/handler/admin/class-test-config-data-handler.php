<?php
/**
 * Test Config Data Handler - Enterprise Module
 *
 * Extends the premium test config data handler to provide enterprise module functionality.
 *
 * @package miniorange-saml-20-single-sign-on
 * @subpackage Module\Enterprise\Handler\Admin
 */

namespace MOSAML\Module\Enterprise\Handler\Admin;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\Module\Premium\Handler\Admin\Test_Config_Data_Handler as Premium_Test_Config_Data_Handler;
use MOSAML\SRC\Interfaces\Form_Data_Handler_Interface;

/**
 * Test Config Data Handler.
 */
class Test_Config_Data_Handler extends Premium_Test_Config_Data_Handler implements Form_Data_Handler_Interface {}
