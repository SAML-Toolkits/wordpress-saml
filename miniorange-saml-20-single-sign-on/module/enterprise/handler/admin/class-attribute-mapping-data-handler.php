<?php
/**
 * This file contains the backend operations related to the Attribute Mapping tab for the enterprise module.
 *
 * @package MOSAML
 */

namespace MOSAML\Module\Enterprise\Handler\Admin;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\Module\Premium\Handler\Admin\Attribute_Mapping_Data_Handler as Premium_Attribute_Mapping_Data_Handler;
use MOSAML\SRC\Interfaces\Form_Data_Handler_Interface;

/**
 * Attribute Mapping Data Handler.
 */
class Attribute_Mapping_Data_Handler extends Premium_Attribute_Mapping_Data_Handler implements Form_Data_Handler_Interface {}
