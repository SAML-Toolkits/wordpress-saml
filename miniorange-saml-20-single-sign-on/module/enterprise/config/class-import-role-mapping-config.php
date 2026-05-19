<?php
/**
 * Enterprise Module - Import Role Mapping Configuration Class
 *
 * Handles role mapping configuration data import for the enterprise module.
 *
 * @package MOSAML\Module\Enterprise\Config
 * @since 1.0.0
 */

namespace MOSAML\Module\Enterprise\Config;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\Module\Premium\Config\Import_Role_Mapping_Config as Premium_Import_Role_Mapping_Config;

/**
 * Enterprise Import Role Mapping Configuration Class
 */
class Import_Role_Mapping_Config extends Premium_Import_Role_Mapping_Config {}
