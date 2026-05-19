<?php
/**
 * Custom Certificate Data Handler file for enterprise plan.
 *
 * @package MOSAML\Module\Enterprise\Handler\Admin
 */

namespace MOSAML\Module\Enterprise\Handler\Admin;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\Module\Premium\Handler\Admin\Certificate_Data_Handler as Premium_Certificate_Data_Handler;
use MOSAML\SRC\Interfaces\Form_Data_Handler_Interface;

/**
 * Custom Certificate Data Handler class for enterprise plan.
 */
class Certificate_Data_Handler extends Premium_Certificate_Data_Handler implements Form_Data_Handler_Interface {}
