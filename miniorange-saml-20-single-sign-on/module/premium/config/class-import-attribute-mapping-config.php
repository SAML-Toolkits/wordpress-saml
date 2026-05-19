<?php
/**
 * Premium Module - Import Attribute Mapping Configuration Class
 *
 * Handles attribute mapping configuration data import for the premium module.
 *
 * @package MOSAML\Module\Premium\Config
 * @since 1.0.0
 */

namespace MOSAML\Module\Premium\Config;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\Module\Standard\Config\Import_Attribute_Mapping_Config as Standard_Import_Attribute_Mapping_Config;

/**
 * Premium Import Attribute Mapping Configuration Class
 */
class Import_Attribute_Mapping_Config extends Standard_Import_Attribute_Mapping_Config {}
