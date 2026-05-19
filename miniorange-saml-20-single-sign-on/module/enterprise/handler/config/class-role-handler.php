<?php
/**
 * Enterprise Role Handler.
 *
 * This file contains the Enterprise Role Handler class which extends
 * the premium role handler with enterprise-level functionality for
 * advanced role processing, conditional assignments, and complex hierarchies.
 *
 * @package miniorange-saml-20-single-sign-on/module/enterprise/handler/config
 * @since 1.0
 */

namespace MOSAML\Module\Enterprise\Handler\Config;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\Module\Premium\Handler\Config\Role_Handler as Premium_Role_Handler;
use MOSAML\Traits\Instance;

/**
 * Role Handler.
 *
 * @package MOSAML\Module\Enterprise\Handler\Config
 */
class Role_Handler extends Premium_Role_Handler {
	use Instance;
}
