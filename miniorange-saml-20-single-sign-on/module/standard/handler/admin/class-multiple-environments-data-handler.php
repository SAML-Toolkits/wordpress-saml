<?php
/**
 * Multiple Environments Data Handler - Standard Module
 *
 * @package miniorange-saml-20-single-sign-on
 */

namespace MOSAML\Module\Standard\Handler\Admin;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\Module\Base\Handler\Admin\Multiple_Environments_Data_Handler as Base_Multiple_Environments_Data_Handler;
use MOSAML\SRC\Interfaces\Form_Data_Handler_Interface;
/**
 * Multiple Environments Data Handler.
 */
class Multiple_Environments_Data_Handler extends Base_Multiple_Environments_Data_Handler implements Form_Data_Handler_Interface {}
