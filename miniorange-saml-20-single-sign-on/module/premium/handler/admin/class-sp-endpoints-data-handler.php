<?php
/**
 * SP Endpoints Data Handler file for premium plan.
 *
 * @package MOSAML\Module\Premium\Handler\Admin
 */

namespace MOSAML\Module\Premium\Handler\Admin;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\Module\Standard\Handler\Admin\SP_Endpoints_Data_Handler as Standard_SP_Endpoints_Data_Handler;
use MOSAML\SRC\Interfaces\Form_Data_Handler_Interface;

/**
 * SP Endpoints Data Handler class for premium plan.
 */
class SP_Endpoints_Data_Handler extends Standard_SP_Endpoints_Data_Handler implements Form_Data_Handler_Interface {}
