<?php
/**
 * Backdoor Login Form Data Handler - Premium Module
 *
 * Extends the standard backdoor login form data handler to provide premium module functionality.
 *
 * @package miniorange-saml-20-single-sign-on
 * @subpackage Module\Premium\Handler\Admin
 */

namespace MOSAML\Module\Premium\Handler\Admin;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\Module\Standard\Handler\Admin\Backdoor_Url_Login_Data_Handler as Standard_Backdoor_Url_Login_Data_Handler;
use MOSAML\SRC\Interfaces\Form_Data_Handler_Interface;

/**
 * Backdoor Login Form Data Handler.
 */
class Backdoor_Url_Login_Data_Handler extends Standard_Backdoor_Url_Login_Data_Handler implements Form_Data_Handler_Interface {}
