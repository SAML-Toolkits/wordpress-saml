<?php
/**
 * SP Endpoints Data Handler file for enterprise plan.
 *
 * @package MOSAML\Module\Enterprise\Handler\Admin
 */

namespace MOSAML\Module\Enterprise\Handler\Admin;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\Module\Premium\Handler\Admin\SP_Endpoints_Data_Handler as Premium_SP_Endpoints_Data_Handler;
use MOSAML\SRC\Interfaces\Form_Data_Handler_Interface;

/**
 * SP Endpoints Data Handler class for enterprise plan.
 */
class SP_Endpoints_Data_Handler extends Premium_SP_Endpoints_Data_Handler implements Form_Data_Handler_Interface {}
