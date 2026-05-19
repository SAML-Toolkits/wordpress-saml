<?php
/**
 * Enterprise Attribute Handler.
 *
 * This file contains the Enterprise Attribute_Handler class that extends premium
 * attribute processing with enterprise-level functionality.
 *
 * @package MOSAML
 * @subpackage Enterprise\Handler\Config
 * @since 1.0.0
 */

namespace MOSAML\Module\Enterprise\Handler\Config;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\Module\Premium\Handler\Config\Attribute_Handler as Premium_Attribute_Handler;
use MOSAML\Traits\Instance;

/**
 * Enterprise Attribute Handler.
 *
 * This class extends the premium attribute handler with enterprise-level functionality.
 *
 * @since 1.0.0
 */
class Attribute_Handler extends Premium_Attribute_Handler {
	use Instance;
}
