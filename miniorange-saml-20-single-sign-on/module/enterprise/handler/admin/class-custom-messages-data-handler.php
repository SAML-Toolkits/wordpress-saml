<?php
/**
 * Custom Messages Data Handler - Enterprise Module
 *
 * Extends the premium custom messages data handler to provide enterprise module functionality.
 *
 * PHP Compatibility: 5.6+
 *
 * @package miniorange-saml-20-single-sign-on
 */

namespace MOSAML\Module\Enterprise\Handler\Admin;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\Module\Premium\Handler\Admin\Custom_Messages_Data_Handler as Premium_Custom_Messages_Data_Handler;
use MOSAML\SRC\Interfaces\Form_Data_Handler_Interface;

/**
 * Custom Messages Data Handler.
 */
class Custom_Messages_Data_Handler extends Premium_Custom_Messages_Data_Handler implements Form_Data_Handler_Interface {}
