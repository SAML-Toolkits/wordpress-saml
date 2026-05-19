<?php
/**
 * Widget Data Handler - Enterprise Module
 *
 * Extends the premium widget data handler to provide enterprise module functionality.
 *
 * PHP Compatibility: 5.6+
 *
 * @package miniorange-saml-20-single-sign-on
 */

namespace MOSAML\Module\Enterprise\Handler\Admin;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\Module\Premium\Handler\Admin\Shortcode_Widget_Data_Handler as Premium_Shortcode_Widget_Data_Handler;
use MOSAML\SRC\Interfaces\Form_Data_Handler_Interface;

/**
 * Widget Data Handler.
 */
class Shortcode_Widget_Data_Handler extends Premium_Shortcode_Widget_Data_Handler implements Form_Data_Handler_Interface {}
