<?php
/**
 * This file contains the backend operations related to the Role Mapping tab for the enterprise module.
 *
 * @package MOSAML
 */

namespace MOSAML\Module\Enterprise\Handler\Admin;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\Module\Premium\Handler\Admin\Role_Assignment_Settings_Data_Handler as Premium_Role_Assignment_Settings_Data_Handler;
use MOSAML\SRC\Interfaces\Form_Data_Handler_Interface;

/**
 * Role Assignment Settings Data Handler.
 */
class Role_Assignment_Settings_Data_Handler extends Premium_Role_Assignment_Settings_Data_Handler implements Form_Data_Handler_Interface {}
