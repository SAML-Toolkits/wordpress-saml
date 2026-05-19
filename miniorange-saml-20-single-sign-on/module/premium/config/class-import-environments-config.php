<?php
/**
 * Premium Module - Import Environments Configuration Class
 *
 * Handles environments configuration data import for the premium module.
 *
 * @package MOSAML\Module\Premium\Config
 * @since 1.0.0
 */

namespace MOSAML\Module\Premium\Config;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\Module\Standard\Config\Import_Environments_Config as Standard_Import_Environments_Config;

/**
 * Premium Import Environments Configuration Class
 */
class Import_Environments_Config extends Standard_Import_Environments_Config {}
