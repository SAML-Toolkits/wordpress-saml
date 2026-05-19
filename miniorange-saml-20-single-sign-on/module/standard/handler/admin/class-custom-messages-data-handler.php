<?php
/**
 * Custom Messages Data Handler - Standard Module
 *
 * Extends the base custom messages data handler to provide standard module functionality.
 *
 * PHP Compatibility: 5.6+
 *
 * @package miniorange-saml-20-single-sign-on
 * @subpackage Module\Standard\Handler\Admin
 */

namespace MOSAML\Module\Standard\Handler\Admin;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\Module\Base\Handler\Admin\Custom_Messages_Data_Handler as Base_Custom_Messages_Data_Handler;
use MOSAML\SRC\Interfaces\Form_Data_Handler_Interface;

/**
 * Custom Messages Data Handler.
 */
class Custom_Messages_Data_Handler extends Base_Custom_Messages_Data_Handler implements Form_Data_Handler_Interface {}
