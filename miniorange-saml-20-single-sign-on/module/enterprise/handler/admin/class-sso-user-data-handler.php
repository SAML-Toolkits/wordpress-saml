<?php
/**
 * SSO User Data Handler - Enterprise Module
 *
 * Extends the premium SSO user data handler to provide enterprise module functionality.
 *
 * @package miniorange-saml-20-single-sign-on
 */

namespace MOSAML\Module\Enterprise\Handler\Admin;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\Module\Premium\Handler\Admin\SSO_User_Data_Handler as Premium_SSO_User_Data_Handler;
use MOSAML\SRC\Interfaces\Form_Data_Handler_Interface;

/**
 * SSO User Data Handler - Enterprise Module.
 *
 * Extends the premium SSO user data handler to provide enterprise module functionality.
 */
class SSO_User_Data_Handler extends Premium_SSO_User_Data_Handler implements Form_Data_Handler_Interface {}
