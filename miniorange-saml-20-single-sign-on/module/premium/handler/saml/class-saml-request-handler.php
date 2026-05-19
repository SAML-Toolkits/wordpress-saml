<?php
/**
 * SAML Request Handler.
 * This class handles the creation, relay state management, and sending of SAML authentication requests for SSO.
 * It provides base logic for SAML request handling, which can be extended by Standard, Premium, and Enterprise handlers.
 *
 * @package MOSAML\Module\Premium\Handler\SAML
 */

namespace MOSAML\Module\Premium\Handler\SAML;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\Module\Standard\Handler\SAML\SAML_Request_Handler as Standard_SAML_Request_Handler;
use MOSAML\SRC\DTO\SAML_Request_DTO;
use MOSAML\Traits\Instance;
use MOSAML\SRC\Utils\Utility;
use MOSAML\SRC\Utils\XML_Utility;
use MOSAML\SRC\Constant\XML_Constants;
use MOSAML\SRC\Constant\Plugin_Options;
use MOSAML\SRC\Exception\Invalid_Assertion_Exception;
use DOMXPath;
use DOMDocument;

/**
 * Premium SAML Request Handler.
 *
 * This class extends the SAML_Request_Handler and provides additional
 * functionality for handling SAML requests.
 */
class SAML_Request_Handler extends Standard_SAML_Request_Handler {

	use Instance;

	/**
	 * Document.
	 *
	 * @var DOMDocument
	 */
	public $document;

	/**
	 * XPath.
	 *
	 * @var DOMXPath
	 */
	public $xpath;

	/**
	 * Handles the SAML request process, including relay state, request creation, and redirect URL setup.
	 *
	 * @param SAML_Request_DTO $saml_request_dto The SAML request DTO to populate and use.
	 * @return void
	 */
	public function handle_saml_request( SAML_Request_DTO $saml_request_dto ) {

		if ( ! empty( $saml_request_dto->get_saml_request() ) ) {

			$this->set_dto_for_logout_request( $saml_request_dto );

			/**
			 * Filter to change the relay state after the SAML Logout Request.
			 *
			 * @param string  $relayState
			 */
			$relay_state = apply_filters( 'mosaml_post_logout_slo_request_relay_state_internal', $saml_request_dto->get_relay_state() );
			$saml_request_dto->set_relay_state( $relay_state );
			$name_id_value = $saml_request_dto->get_name_id();
			$idp_details   = Utility::get_handler_object( 'sp_setup_data', true, 'admin' )->get_data( array( 'entity_id' => $saml_request_dto->get_issuer() ) );

			apply_filters( 'mosaml_idp_slo_triggered_internal', $name_id_value, $idp_details->idp_name );

			if ( session_status() === PHP_SESSION_NONE ) {
				session_start();
			}
			$_SESSION['mo_saml_logout_request']     = $saml_request_dto->get_saml_request();
			$_SESSION['mo_saml_logout_relay_state'] = $relay_state;
			wp_logout();
			wp_safe_redirect( $relay_state );
			exit;
		}

		$this->get_relay_state( $saml_request_dto );

		$this->create_saml_request( $saml_request_dto );

		$this->send_saml_request( $saml_request_dto );
	}

	/**
	 * Set the DTO for SAML logout request received from the IDP.
	 *
	 * @param SAML_Request_DTO $saml_request_dto The SAML request DTO to set.
	 * @return void
	 */
	public function set_dto_for_logout_request( SAML_Request_DTO $saml_request_dto ) {
		$this->decode_and_load_saml_request( $saml_request_dto );
		$saml_request_xml = $this->document->firstChild;

		// phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- This is a property of the DOMDocument object.
		if ( 'LogoutRequest' !== $saml_request_xml->localName ) {
			return;
		}

		XML_Utility::validate_and_set_nodes( $this, $saml_request_xml, $saml_request_dto, XML_Constants::NODES_QUERY_MAP['request'] );
	}

	/**
	 * Decodes and loads the SAML request received from the IDP.
	 *
	 * @param SAML_Request_DTO $saml_request_dto The SAML request DTO to decode and load.
	 * @return void
	 */
	public function decode_and_load_saml_request( SAML_Request_DTO $saml_request_dto ) {

		$decoded_response = XML_Utility::validate_compressed_xml( $saml_request_dto->get_saml_request(), Plugin_Options::SAML_REQUEST );

		$this->document = XML_Utility::safe_load_xml( $decoded_response );
		$this->xpath    = new DOMXPath( $this->document );

		foreach ( XML_Constants::RESPONSE_NAMESPACES as $prefix => $uri ) {
			$this->xpath->registerNamespace( $prefix, $uri );
		}
	}

	/**
	 * Function to validate the assertion version.
	 *
	 * @param SAML_Request_DTO $dto The DTO object.
	 * @return void
	 * @throws Invalid_Assertion_Exception If the version is not supported.
	 */
	public function validate_version( SAML_Request_DTO $dto ) {
		if ( '2.0' !== $dto->get_request_version() ) {
			throw new Invalid_Assertion_Exception( 'Unsupported Version : ' . esc_html( $dto->get_request_version() ) );
		}
	}

	/**
	 * Builds the SAML login redirect URL and sets it in the SAML request DTO.
	 *
	 * @param SAML_Request_DTO $saml_request_dto The SAML request DTO to update.
	 * @return void
	 */
	public function send_saml_request( SAML_Request_DTO $saml_request_dto ) {
		parent::send_saml_request( $saml_request_dto );

		//phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Nonce verification not required here.
		$request_array = $this->sanitize_associative_array( $_REQUEST );

		$redirect = $saml_request_dto->get_redirect();

		$redirect = $this->append_params_redirect_binding( $redirect, $request_array );

		$saml_request_dto->set_redirect( $redirect );
	}

	/**
	 * Used to sanitize an associative array.
	 *
	 * @param array $raw_array Un-santized associative array.
	 * @return array
	 */
	public function sanitize_associative_array( $raw_array ) {
		$sanitized_array = array();
		foreach ( $raw_array as $key => $value ) {
			if ( is_array( $value ) ) {
				$sanitized_array[ $key ] = $this->sanitize_associative_array( $value );
			} else {
				$sanitized_array[ $key ] = sanitize_text_field( $value );
			}
		}
		return $sanitized_array;
	}

	/**
	 * Used for appending additional parameters in case of redirect binding.
	 *
	 * @param string $base_url The base URL to append parameters to.
	 * @param array  $request_array $_REQUEST Object.
	 * @return string
	 */
	public function append_params_redirect_binding( $base_url, $request_array ) {
		$params = array();
		foreach ( $request_array as $key => $value ) {
			if ( 'option' !== $key ) {
				$value          = Utility::mo_saml_is_array( $value );
				$params[ $key ] = $value;
			}
		}
		return add_query_arg( $params, $base_url );
	}
}
