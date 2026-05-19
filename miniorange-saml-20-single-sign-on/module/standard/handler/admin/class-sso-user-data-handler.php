<?php
/**
 * SSO User Data Handler - Standard Module
 *
 * Extends the base SSO user data handler to provide standard module functionality.
 *
 * PHP Compatibility: 5.6+
 *
 * @package miniorange-saml-20-single-sign-on
 * @subpackage Module\Standard\Handler\Admin
 */

namespace MOSAML\Module\Standard\Handler\Admin;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\Module\Base\Handler\Admin\SSO_User_Data_Handler as Base_SSO_User_Data_Handler;
use MOSAML\SRC\Interfaces\Form_Data_Handler_Interface;

/**
 * SSO User Data Handler.
 */
class SSO_User_Data_Handler extends Base_SSO_User_Data_Handler implements Form_Data_Handler_Interface {}
