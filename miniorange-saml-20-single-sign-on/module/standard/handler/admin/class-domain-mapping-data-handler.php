<?php
/**
 * Domain Mapping Data Handler - Standard Module
 *
 * Extends the base domain mapping data handler. Domain mapping is an enterprise feature,
 * so this class provides no additional functionality over the base class.
 *
 * PHP Compatibility: 5.6+
 *
 * @package miniorange-saml-20-single-sign-on
 * @subpackage Module\Standard\Handler\Admin
 */

namespace MOSAML\Module\Standard\Handler\Admin;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\Module\Base\Handler\Admin\Domain_Mapping_Data_Handler as Base_Domain_Mapping_Data_Handler;
use MOSAML\SRC\Interfaces\Form_Data_Handler_Interface;

/**
 * Domain Mapping Data Handler.
 *
 * Domain mapping is an enterprise feature, so this standard implementation
 * provides no additional functionality beyond the base class.
 */
class Domain_Mapping_Data_Handler extends Base_Domain_Mapping_Data_Handler implements Form_Data_Handler_Interface {}
