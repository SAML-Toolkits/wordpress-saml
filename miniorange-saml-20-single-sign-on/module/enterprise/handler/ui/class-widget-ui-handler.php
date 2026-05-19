<?php
/**
 * Widget UI Handler - Enterprise Module
 *
 * Extends premium widget handler for enterprise module.
 *
 * @package miniorange-saml-20-single-sign-on
 * @subpackage Module\Enterprise\Handler\UI
 */

namespace MOSAML\Module\Enterprise\Handler\UI;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\Module\Premium\Handler\UI\Widget_UI_Handler as Premium_Widget_UI_Handler;

/**
 * Widget UI Handler - Enterprise Module.
 * Inherits all customization features from Premium.
 */
class Widget_UI_Handler extends Premium_Widget_UI_Handler {}
