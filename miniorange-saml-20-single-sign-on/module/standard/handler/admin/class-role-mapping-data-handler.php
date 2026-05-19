<?php
/**
 * This file contains the backend operations related to the Role Mapping tab for the standard module.
 *
 * @package MOSAML
 */

namespace MOSAML\Module\Standard\Handler\Admin;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\Module\Base\Handler\Admin\Role_Mapping_Data_Handler as Base_Role_Mapping_Data_Handler;
use MOSAML\SRC\Interfaces\Form_Data_Handler_Interface;
use MOSAML\SRC\Utils\Utility;

/**
 * Role Mapping Handler.
 */
class Role_Mapping_Data_Handler extends Base_Role_Mapping_Data_Handler implements Form_Data_Handler_Interface {}
