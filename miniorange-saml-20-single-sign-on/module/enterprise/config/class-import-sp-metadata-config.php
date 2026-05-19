<?php
/**
 * Enterprise Module - Import SP Metadata Configuration Class
 *
 * Handles SP metadata configuration data import for the enterprise module.
 *
 * @package MOSAML\Module\Enterprise\Config
 * @since 1.0.0
 */

namespace MOSAML\Module\Enterprise\Config;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\Module\Premium\Config\Import_SP_Metadata_Config as Premium_Import_SP_Metadata_Config;

/**
 * Enterprise Import SP Metadata Configuration Class
 */
class Import_SP_Metadata_Config extends Premium_Import_SP_Metadata_Config {}
