<?php
/**
 * Premium Enable RSS Access Data Handler.
 *
 * @package miniorange-saml-20-single-sign-on/module/premium/handler/admin
 */

namespace MOSAML\Module\Premium\Handler\Admin;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\Module\Standard\Handler\Admin\RSS_Feed_Access_Data_Handler as Standard_Enable_RSS_Access_Data_Handler;
use MOSAML\SRC\Interfaces\Form_Data_Handler_Interface;

/**
 * Premium Enable RSS Access Data Handler.
 */
class RSS_Feed_Access_Data_Handler extends Standard_Enable_RSS_Access_Data_Handler implements Form_Data_Handler_Interface {}
