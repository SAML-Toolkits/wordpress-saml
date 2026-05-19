<?php
/**
 * Account Info Data Handler - Enterprise Module
 *
 * @package miniorange-saml-20-single-sign-on
 * @subpackage Module\Enterprise\Handler\Admin
 */

namespace MOSAML\Module\Enterprise\Handler\Admin;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\Module\Premium\Handler\Admin\Account_Info_Data_Handler as Premium_Account_Info_Data_Handler;
use MOSAML\SRC\Interfaces\Form_Data_Handler_Interface;



/**
 * Account Info Data Handler - Enterprise Module
 */
class Account_Info_Data_Handler extends Premium_Account_Info_Data_Handler implements Form_Data_Handler_Interface {}
