<?php
/**
 * Widget Data Handler - Premium Module
 *
 * Extends the standard widget data handler to provide premium module functionality.
 *
 * @package miniorange-saml-20-single-sign-on
 * @subpackage Module\Premium\Handler\Admin
 */

namespace MOSAML\Module\Premium\Handler\Admin;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\Module\Standard\Handler\Admin\Shortcode_Widget_Data_Handler as Standard_Shortcode_Widget_Data_Handler;
use MOSAML\SRC\Interfaces\Form_Data_Handler_Interface;

/**
 * Widget Data Handler.
 */
class Shortcode_Widget_Data_Handler extends Standard_Shortcode_Widget_Data_Handler implements Form_Data_Handler_Interface {}
