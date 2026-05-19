<?php
/**
 * Metadata Sync Data Handler for Enterprise version.
 * Extends Premium metadata sync with Enterprise-specific features.
 *
 * @package miniorange-saml-20-single-sign-on/module/enterprise/handler/admin
 */

namespace MOSAML\Module\Enterprise\Handler\Admin;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\Module\Premium\Handler\Admin\Metadata_Sync_Data_Handler as Premium_Metadata_Sync_Data_Handler;
use MOSAML\SRC\Interfaces\Form_Data_Handler_Interface;

/**
 * Enterprise Metadata Sync Data Handler.
 *
 * Extends Premium functionality with Enterprise version specific features.
 */
class Metadata_Sync_Data_Handler extends Premium_Metadata_Sync_Data_Handler implements Form_Data_Handler_Interface {}
