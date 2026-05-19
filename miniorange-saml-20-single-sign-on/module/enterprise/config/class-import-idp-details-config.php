<?php
/**
 * Enterprise Module - Import IDP Details Configuration Class
 *
 * Handles IDP details configuration data import for the enterprise module.
 *
 * @package MOSAML\Module\Enterprise\Config
 * @since 1.0.0
 */

namespace MOSAML\Module\Enterprise\Config;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\Module\Premium\Config\Import_Idp_Details_Config as Premium_Import_Idp_Details_Config;

/**
 * Enterprise Import IDP Details Configuration Class
 */
class Import_Idp_Details_Config extends Premium_Import_Idp_Details_Config {}
