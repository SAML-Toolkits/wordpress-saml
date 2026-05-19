<?php
/**
 * This file contains the backend operations related to the Role Mapping Advanced Settings tab for the standard module.
 *
 * @package MOSAML
 */

namespace MOSAML\Module\Standard\Handler\Admin;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\Module\Base\Handler\Admin\Role_Mapping_Advanced_Settings_Data_Handler as Base_Role_Mapping_Advanced_Settings_Data_Handler;
use MOSAML\SRC\Interfaces\Form_Data_Handler_Interface;

/**
 * Role Mapping Advanced Settings Handler.
 */
class Role_Mapping_Advanced_Settings_Data_Handler extends Base_Role_Mapping_Advanced_Settings_Data_Handler implements Form_Data_Handler_Interface {}
