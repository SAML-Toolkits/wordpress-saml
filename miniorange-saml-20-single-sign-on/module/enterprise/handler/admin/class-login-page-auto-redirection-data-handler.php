<?php
/**
 * Enterprise Redirect From WP Login Form Data Handler
 *
 * @package miniorange-saml-20-single-sign-on/module/enterprise/handler/admin
 */

namespace MOSAML\Module\Enterprise\Handler\Admin;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\Module\Premium\Handler\Admin\Login_Page_Auto_Redirection_Data_Handler as Premium_Login_Page_Auto_Redirection_Data_Handler;

/**
 * Enterprise Redirect From WP Login Form Data Handler
 *
 * Extends premium functionality for redirecting from WordPress login form.
 */
class Login_Page_Auto_Redirection_Data_Handler extends Premium_Login_Page_Auto_Redirection_Data_Handler {}
