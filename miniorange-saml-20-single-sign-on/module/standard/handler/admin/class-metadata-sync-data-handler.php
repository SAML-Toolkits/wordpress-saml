<?php
/**
 * Metadata Sync Data Handler for Standard version.
 * Extends Base but still provides stub implementation - metadata sync requires Premium+.
 *
 * @package miniorange-saml-20-single-sign-on/module/standard/handler/admin
 */

namespace MOSAML\Module\Standard\Handler\Admin;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\Module\Base\Handler\Admin\Metadata_Sync_Data_Handler as Base_Metadata_Sync_Data_Handler;
use MOSAML\SRC\Interfaces\Form_Data_Handler_Interface;

/**
 * Standard Metadata Sync Data Handler.
 * Extends Base but metadata sync functionality still not available in Standard version.
 */
class Metadata_Sync_Data_Handler extends Base_Metadata_Sync_Data_Handler implements Form_Data_Handler_Interface {}
