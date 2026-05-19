<?php
/**
 * Enterprise Relay State Data Handler.
 *
 * @package miniorange-saml-20-single-sign-on/module/enterprise/handler/admin
 */

namespace MOSAML\Module\Enterprise\Handler\Admin;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\Module\Premium\Handler\Admin\Relay_State_Data_Handler as Premium_Relay_State_Data_Handler;
use MOSAML\SRC\Interfaces\Form_Data_Handler_Interface;

/**
 * Enterprise Relay State Data Handler.
 */
class Relay_State_Data_Handler extends Premium_Relay_State_Data_Handler implements Form_Data_Handler_Interface {}
