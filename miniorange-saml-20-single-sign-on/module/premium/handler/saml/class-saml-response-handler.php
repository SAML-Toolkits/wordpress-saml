<?php
/**
 * SAML Response Handler file for Premium Version.
 *
 * @package MOSAML\Module\Premium\Handler\SAML
 */

namespace MOSAML\Module\Premium\Handler\SAML;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\Module\Standard\Handler\SAML\SAML_Response_Handler as Standard_SAML_Response_Handler;
use MOSAML\SRC\Utils\XML_Utility;
use MOSAML\SRC\Constant\XML_Constants;
use MOSAML\SRC\Exception\Invalid_XML_Exception;

/**
 * SAML Response Handler class for Premium Version.
 *
 * This class handles the basic parsing of SAML responses. It focuses on
 * extracting the response envelope and delegating assertion parsing to
 * the SAML_Assertion_Parser class.
 *
 * @package MOSAML\Module\Premium\Handler
 */
class SAML_Response_Handler extends Standard_SAML_Response_Handler {

	/**
	 * Handles the case of Logout Response from IdP and sets the DTO accordingly.
	 *
	 * @return void
	 * @throws Invalid_XML_Exception If the SAML response is invalid.
	 */
	public function set_response_dto() {

		$response_element = $this->document->firstChild;
		// PHPCS:Ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- This is a property of the DOMElement object.
		if ( 'LogoutResponse' === $response_element->localName ) {

			$this->dto->set_logout_response( true );
			$logout_response_node = $this->xpath->query( './samlp:LogoutResponse', $this->document );
			if ( 1 !== $logout_response_node->length ) {
				throw new Invalid_XML_Exception( 'Invalid SAML response.' );
			}
			$logout_response_node_item = $logout_response_node->item( 0 );
			$this->dto->set_root_node( $logout_response_node_item );
			XML_Utility::validate_and_set_nodes( $this, $logout_response_node_item, $this->dto, XML_Constants::NODES_QUERY_MAP['response'] );
		} else {
			parent::set_response_dto();
		}
	}
}
