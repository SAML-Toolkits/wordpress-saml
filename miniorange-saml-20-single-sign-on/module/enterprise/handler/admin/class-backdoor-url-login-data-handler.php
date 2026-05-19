<?php
/**
 * Backdoor Login Form Data Handler - Enterprise Module
 *
 * Extends the premium backdoor login form data handler to provide enterprise module functionality.
 *
 * PHP Compatibility: 5.6+
 *
 * @package miniorange-saml-20-single-sign-on
 */

namespace MOSAML\Module\Enterprise\Handler\Admin;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\Module\Premium\Handler\Admin\Backdoor_Url_Login_Data_Handler as Premium_Backdoor_Url_Login_Data_Handler;
use MOSAML\SRC\Interfaces\Form_Data_Handler_Interface;

/**
 * Backdoor Login Form Data Handler.
 */
class Backdoor_Url_Login_Data_Handler extends Premium_Backdoor_Url_Login_Data_Handler implements Form_Data_Handler_Interface {}
