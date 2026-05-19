<?php
/**
 * SSO User Tag Handler - Enterprise Module
 *
 * Handles SSO user tag configuration for the enterprise module.
 *
 * @package MOSAML\Module\Enterprise\Handler\Config
 */

namespace MOSAML\Module\Enterprise\Handler\Config;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\Module\Premium\Handler\Config\SSO_User_Tag_Handler as Premium_SSO_User_Tag_Handler;

/**
 * SSO User Tag Handler.
 */
class SSO_User_Tag_Handler extends Premium_SSO_User_Tag_Handler {}
