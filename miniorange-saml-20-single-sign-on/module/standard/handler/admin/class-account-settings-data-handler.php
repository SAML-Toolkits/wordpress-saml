<?php
/**
 * Account Settings Data Handler.
 *
 * @package miniorange-saml-20-single-sign-on
 */

namespace MOSAML\Module\Standard\Handler\Admin;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\Module\Base\Handler\Admin\Account_Settings_Data_Handler as Base_Account_Settings_Data_Handler;
use MOSAML\SRC\Interfaces\Form_Data_Handler_Interface;

/**
 * Account Settings Data Handler.
 */
class Account_Settings_Data_Handler extends Base_Account_Settings_Data_Handler implements Form_Data_Handler_Interface {}
