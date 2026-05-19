<?php
/**
 * Premium Module - Import SSO Configuration Class
 *
 * Handles SSO configuration data import for the premium module.
 *
 * @package MOSAML\Module\Premium\Config
 * @since 1.0.0
 */

namespace MOSAML\Module\Premium\Config;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\Module\Standard\Config\Import_SSO_Config as Standard_Import_SSO_Config;

/**
 * Premium Import SSO Configuration Class
 */
class Import_SSO_Config extends Standard_Import_SSO_Config {}
