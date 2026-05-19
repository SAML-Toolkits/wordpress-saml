<?php
/**
 * User Logout Handler file for Enterprise Version.
 *
 * @package MOSAML\Module\Enterprise\Handler
 */

namespace MOSAML\Module\Enterprise\Handler;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\Module\Premium\Handler\User_Logout_Handler as Premium_User_Logout_Handler;

/**
 * User Logout Handler for Enterprise Version.
 *
 * This class handles the user logout process.
 */
class User_Logout_Handler extends Premium_User_Logout_Handler {}
