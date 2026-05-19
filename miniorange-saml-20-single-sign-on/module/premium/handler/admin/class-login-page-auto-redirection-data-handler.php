<?php
/**
 * Premium Redirect From WP Login Form Data Handler
 *
 * @package miniorange-saml-20-single-sign-on/module/premium/handler/admin
 */

namespace MOSAML\Module\Premium\Handler\Admin;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\Module\Standard\Handler\Admin\Login_Page_Auto_Redirection_Data_Handler as Standard_Login_Page_Auto_Redirection_Data_Handler;

/**
 * Premium Redirect From WP Login Form Data Handler
 *
 * Extends standard functionality for redirecting from WordPress login form.
 */
class Login_Page_Auto_Redirection_Data_Handler extends Standard_Login_Page_Auto_Redirection_Data_Handler {}
