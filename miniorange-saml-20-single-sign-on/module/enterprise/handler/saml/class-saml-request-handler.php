<?php
/**
 * SAML Request Handler.
 * This class handles the creation, relay state management, and sending of SAML authentication requests for SSO.
 * It provides base logic for SAML request handling, which can be extended by Standard, Premium, and Enterprise handlers.
 *
 * @package MOSAML\Module\Enterprise\Handler\SAML
 */

namespace MOSAML\Module\Enterprise\Handler\SAML;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\Module\Premium\Handler\SAML\SAML_Request_Handler as Premium_SAML_Request_Handler;
use MOSAML\Traits\Instance;

/**
 * Enterprise SAML Request Handler.
 *
 * This class extends the SAML_Request_Handler and provides additional
 * functionality for handling SAML requests.
 */
class SAML_Request_Handler extends Premium_SAML_Request_Handler {

	use Instance;
}
