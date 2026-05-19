<?php
/**
 * Premium Module - Import Redirection Configuration Class
 *
 * Handles redirection configuration data import for the premium module.
 *
 * @package MOSAML\Module\Premium\Config
 * @since 1.0.0
 */

namespace MOSAML\Module\Premium\Config;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\Module\Standard\Config\Import_Redirection_Config as Standard_Import_Redirection_Config;

/**
 * Premium Import Redirection Configuration Class
 */
class Import_Redirection_Config extends Standard_Import_Redirection_Config {}
