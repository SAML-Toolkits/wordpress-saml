<?php
/**
 * Premium Module - Import IDP Details Configuration Class
 *
 * Handles IDP details configuration data import for the premium module.
 *
 * @package MOSAML\Module\Premium\Config
 * @since 1.0.0
 */

namespace MOSAML\Module\Premium\Config;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\Module\Standard\Config\Import_Idp_Details_Config as Standard_Import_Idp_Details_Config;

/**
 * Premium Import IDP Details Configuration Class
 */
class Import_Idp_Details_Config extends Standard_Import_Idp_Details_Config {}
