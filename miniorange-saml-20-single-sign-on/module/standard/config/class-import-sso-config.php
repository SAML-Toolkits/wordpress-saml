<?php
/**
 * Standard Module - Import SSO Configuration Class
 *
 * Handles SSO configuration data import for the standard module.
 *
 * @package MOSAML\Module\Standard\Config
 * @since 1.0.0
 */

namespace MOSAML\Module\Standard\Config;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\Module\Base\Config\Import_SSO_Config as Base_Import_SSO_Config;

/**
 * Standard Import SSO Configuration Class
 */
class Import_SSO_Config extends Base_Import_SSO_Config {}
