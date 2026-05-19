<?php
/**
 * Enterprise Module - Import Attribute Mapping Configuration Class
 *
 * Handles attribute mapping configuration data import for the enterprise module.
 *
 * @package MOSAML\Module\Enterprise\Config
 * @since 1.0.0
 */

namespace MOSAML\Module\Enterprise\Config;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\Module\Premium\Config\Import_Attribute_Mapping_Config as Premium_Import_Attribute_Mapping_Config;

/**
 * Enterprise Import Attribute Mapping Configuration Class
 */
class Import_Attribute_Mapping_Config extends Premium_Import_Attribute_Mapping_Config {}
