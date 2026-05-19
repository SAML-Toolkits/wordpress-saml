<?php
/**
 * Test Config Data Handler - Standard Module
 *
 * Extends the base test config data handler to provide standard module functionality.
 *
 * @package miniorange-saml-20-single-sign-on
 * @subpackage Module\Standard\Handler\Admin
 */

namespace MOSAML\Module\Standard\Handler\Admin;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\Module\Base\Handler\Admin\Test_Config_Data_Handler as Base_Test_Config_Data_Handler;
use MOSAML\SRC\Interfaces\Form_Data_Handler_Interface;

/**
 * Test Config Data Handler.
 */
class Test_Config_Data_Handler extends Base_Test_Config_Data_Handler implements Form_Data_Handler_Interface {}
