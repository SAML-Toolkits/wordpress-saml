<?php
/**
 * This file includes the save and get function for SP Organization as per the standard plan.
 *
 * @package MOSAML\Module\Standard\Handler\Admin
 */

namespace MOSAML\Module\Standard\Handler\Admin;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\Module\Base\Handler\Admin\SP_Organization_Data_Handler as Base_SP_Organization_Data_Handler;
use MOSAML\SRC\Interfaces\Form_Data_Handler_Interface;

/**
 * SP Organization Data Handler.
 */
class SP_Organization_Data_Handler extends Base_SP_Organization_Data_Handler implements Form_Data_Handler_Interface {}
