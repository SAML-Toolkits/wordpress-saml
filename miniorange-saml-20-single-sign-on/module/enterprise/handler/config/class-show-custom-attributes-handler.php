<?php
/**
 * Show Custom Attribute Handler.
 *
 * This file contains the Base Show_Custom_Attribute_Handler class that handles the display of custom attributes.
 *
 * @package MOSAML
 * @subpackage Base\Handler\Config
 * @since 1.0.0
 */

namespace MOSAML\Module\Enterprise\Handler\Config;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\Module\Premium\Handler\Config\Show_Custom_Attributes_Handler as Premium_Show_Custom_Attribute_Handler;

/**
 * Show Custom Attribute Handler.
 *
 * This class handles the display of custom attributes.
 *
 * @since 1.0.0
 */
class Show_Custom_Attributes_Handler extends Premium_Show_Custom_Attribute_Handler{}
