<?php
/**
 * Custom Certificate Data Handler file for standard plan.
 *
 * @package MOSAML\Module\Standard\Handler\Admin
 */

namespace MOSAML\Module\Standard\Handler\Admin;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\Module\Base\Handler\Admin\Certificate_Data_Handler as Base_Certificate_Data_Handler;
use MOSAML\SRC\Interfaces\Form_Data_Handler_Interface;

/**
 * Custom Certificate Data Handler class for standard plan.
 */
class Certificate_Data_Handler extends Base_Certificate_Data_Handler implements Form_Data_Handler_Interface {}
