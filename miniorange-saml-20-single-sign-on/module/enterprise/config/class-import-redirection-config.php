<?php
/**
 * Enterprise Module - Import Redirection Configuration Class
 *
 * Handles redirection configuration data import for the enterprise module.
 *
 * @package MOSAML\Module\Enterprise\Config
 * @since 1.0.0
 */

namespace MOSAML\Module\Enterprise\Config;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\Module\Premium\Config\Import_Redirection_Config as Premium_Import_Redirection_Config;

/**
 * Enterprise Import Redirection Configuration Class
 */
class Import_Redirection_Config extends Premium_Import_Redirection_Config {}
