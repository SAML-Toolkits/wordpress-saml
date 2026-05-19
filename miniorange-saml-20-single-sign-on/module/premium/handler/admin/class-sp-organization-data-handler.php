<?php
/**
 * This file includes the save and get function for SP Organization as per the premium plan.
 *
 * @package MOSAML\Module\Premium\Handler\Admin
 */

namespace MOSAML\Module\Premium\Handler\Admin;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\Module\Standard\Handler\Admin\SP_Organization_Data_Handler as Standard_SP_Organization_Data_Handler;
use MOSAML\SRC\Interfaces\Form_Data_Handler_Interface;

/**
 * SP Organization Data Handler.
 */
class SP_Organization_Data_Handler extends Standard_SP_Organization_Data_Handler implements Form_Data_Handler_Interface {}
