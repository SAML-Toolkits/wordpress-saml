<?php
/**
 * Domain Mapping Data Handler - Premium Module
 *
 * Extends the standard domain mapping data handler. Domain mapping is an enterprise feature,
 * so this class provides no additional functionality over the standard class.
 *
 * @package miniorange-saml-20-single-sign-on
 * @subpackage Module\Premium\Handler\Admin
 */

namespace MOSAML\Module\Premium\Handler\Admin;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\Module\Standard\Handler\Admin\Domain_Mapping_Data_Handler as Standard_Domain_Mapping_Data_Handler;
use MOSAML\SRC\Interfaces\Form_Data_Handler_Interface;

/**
 * Domain Mapping Data Handler.
 *
 * Domain mapping is an enterprise feature, so this premium implementation
 * provides no additional functionality beyond the standard class.
 */
class Domain_Mapping_Data_Handler extends Standard_Domain_Mapping_Data_Handler implements Form_Data_Handler_Interface {}
