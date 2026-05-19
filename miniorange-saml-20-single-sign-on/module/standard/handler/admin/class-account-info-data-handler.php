<?php
/**
 * Account Info Data Handler - Standard Module
 *
 * @package miniorange-saml-20-single-sign-on
 * @subpackage Module\Standard\Handler\Admin
 */

namespace MOSAML\Module\Standard\Handler\Admin;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\Module\Base\Handler\Admin\Account_Info_Data_Handler as Base_Account_Info_Data_Handler;
use MOSAML\SRC\Interfaces\Form_Data_Handler_Interface;

/**
 * Account Info Data Handler - Standard Module
 */
class Account_Info_Data_Handler extends Base_Account_Info_Data_Handler implements Form_Data_Handler_Interface {}
