<?php
/**
 * Enterprise Module - Import SSO Configuration Class
 *
 * Handles SSO configuration data import for the enterprise module.
 *
 * @package MOSAML\Module\Enterprise\Config
 * @since 1.0.0
 */

namespace MOSAML\Module\Enterprise\Config;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\Module\Premium\Config\Import_SSO_Config as Premium_Import_SSO_Config;

/**
 * Enterprise Import SSO Configuration Class
 */
class Import_SSO_Config extends Premium_Import_SSO_Config {}
