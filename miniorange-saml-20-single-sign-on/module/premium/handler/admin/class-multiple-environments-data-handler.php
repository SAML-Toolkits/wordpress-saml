<?php
/**
 * Multiple Environments Data Handler - Premium Module
 *
 * @package miniorange-saml-20-single-sign-on
 */

namespace MOSAML\Module\Premium\Handler\Admin;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\Module\Standard\Handler\Admin\Multiple_Environments_Data_Handler as Standard_Multiple_Environments_Data_Handler;
use MOSAML\SRC\Interfaces\Form_Data_Handler_Interface;

/**
 * Multiple Environments Data Handler.
 */
class Multiple_Environments_Data_Handler extends Standard_Multiple_Environments_Data_Handler implements Form_Data_Handler_Interface {}
