<?php
/**
 * Enterprise Module - Import Environments Configuration Class
 *
 * Handles environments configuration data import for the enterprise module.
 *
 * @package MOSAML\Module\Enterprise\Config
 * @since 1.0.0
 */

namespace MOSAML\Module\Enterprise\Config;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\Module\Premium\Config\Import_Environments_Config as Premium_Import_Environments_Config;

/**
 * Enterprise Import Environments Configuration Class
 */
class Import_Environments_Config extends Premium_Import_Environments_Config {}
