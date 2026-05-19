<?php
/**
 * Enterprise Enable RSS Access Data Handler.
 *
 * @package miniorange-saml-20-single-sign-on/module/enterprise/handler/admin
 */

namespace MOSAML\Module\Enterprise\Handler\Admin;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\Module\Premium\Handler\Admin\RSS_Feed_Access_Data_Handler as Premium_Enable_RSS_Access_Data_Handler;
use MOSAML\SRC\Interfaces\Form_Data_Handler_Interface;

/**
 * Enterprise Enable RSS Access Data Handler.
 */
class RSS_Feed_Access_Data_Handler extends Premium_Enable_RSS_Access_Data_Handler implements Form_Data_Handler_Interface {}
