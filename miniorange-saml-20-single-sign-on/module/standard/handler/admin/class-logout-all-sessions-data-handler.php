<?php
/**
 * Logout All Sessions Data Handler file for enterprise plan.
 *
 * @package MOSAML\Module\Enterprise\Handler\Admin
 */

namespace MOSAML\Module\Standard\Handler\Admin;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\Module\Base\Handler\Admin\Logout_All_Sessions_Data_Handler as Base_Logout_All_Sessions_Data_Handler;
use MOSAML\SRC\Interfaces\Form_Data_Handler_Interface;

/**
 * Logout All Sessions Data Handler class for enterprise plan.
 */
class Logout_All_Sessions_Data_Handler extends Base_Logout_All_Sessions_Data_Handler implements Form_Data_Handler_Interface {}
