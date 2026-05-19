<?php
/**
 * SAML Response Handler file for Enterprise Version.
 *
 * @package MOSAML\Module\Enterprise\Handler\SAML
 */

namespace MOSAML\Module\Enterprise\Handler\SAML;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\Module\Premium\Handler\SAML\SAML_Response_Handler as Premium_SAML_Response_Handler;

/**
 * SAML Response Handler class for Enterprise Version.
 *
 * This class handles the basic parsing of SAML responses. It focuses on
 * extracting the response envelope and delegating assertion parsing to
 * the SAML_Assertion_Parser class.
 *
 * @package MOSAML\Module\Enterprise\Handler
 */
class SAML_Response_Handler extends Premium_SAML_Response_Handler {}
