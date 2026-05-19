<?php
/**
 * Premium Module - Import SP Metadata Configuration Class
 *
 * Handles SP metadata configuration data import for the premium module.
 *
 * @package MOSAML\Module\Premium\Config
 * @since 1.0.0
 */

namespace MOSAML\Module\Premium\Config;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\Module\Standard\Config\Import_SP_Metadata_Config as Standard_Import_SP_Metadata_Config;

/**
 * Premium Import SP Metadata Configuration Class
 */
class Import_SP_Metadata_Config extends Standard_Import_SP_Metadata_Config {}
