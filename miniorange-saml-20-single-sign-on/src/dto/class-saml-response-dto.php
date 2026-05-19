<?php
/**
 * SAML Response DTO.
 *
 * @package MOSAML\SRC\DTO
 */

namespace MOSAML\SRC\DTO;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * SAML Response DTO.
 *
 * @package MOSAML\SRC\DTO
 */
class SAML_Response_DTO {

	/**
	 * Root node.
	 *
	 * @var DOMElement
	 */
	private $root_node;

	/**
	 * Destination.
	 *
	 * @var string
	 */
	private $response_destination;

	/**
	 * Assertions.
	 *
	 * @var Assertions_DTO[]
	 */
	private $assertions = array();

	/**
	 * Certificate.
	 *
	 * @var string|array
	 */
	private $certificates;

	/**
	 * Signature data.
	 *
	 * @var string
	 */
	private $signature_node;

	/**
	 * XML Security DSig Object.
	 *
	 * @var XMLSecurityDSig
	 */
	private $xml_sec_dsig_obj;

	/**
	 * Signature method.
	 *
	 * @var string
	 */
	private $signature_method;

	/**
	 * Signature method algorithm.
	 *
	 * @var string
	 */
	private $signature_method_algorithm;

	/**
	 * Issuer.
	 *
	 * @var string
	 */
	private $issuer;

	/**
	 * Status.
	 *
	 * @var array
	 */
	private $status_code_value;

	/**
	 * Status message.
	 *
	 * @var string
	 */
	private $status_message;

	/**
	 * Logout response.
	 *
	 * @var bool
	 */
	private $logout_response = false;

	/**
	 * IDP ID.
	 *
	 * @var string
	 */
	private $idp_pk;

	/**
	 * Relay state.
	 *
	 * @var string
	 */
	private $relay_state;

	/**
	 * IdP Details Object.
	 *
	 * @var object
	 */
	private $idp_details;

	/**
	 * SP Details Object.
	 *
	 * @var object
	 */
	private $sp_details;

	/**
	 * Get IDP Primary Key.
	 *
	 * @return string
	 */
	public function get_idp_pk() {
		return $this->idp_pk;
	}

	/**
	 * Set IDP Primary Key.
	 *
	 * @param string $idp_pk IDP ID.
	 */
	public function set_idp_pk( $idp_pk ) {
		$this->idp_pk = $idp_pk;
	}

	/**
	 * Get relay state.
	 *
	 * @return string
	 */
	public function get_relay_state() {
		return $this->relay_state;
	}

	/**
	 * Set relay state.
	 *
	 * @param string $relay_state Relay state.
	 */
	public function set_relay_state( $relay_state ) {
		$this->relay_state = $relay_state;
	}

	/**
	 * Get the root node.
	 *
	 * @return DOMElement
	 */
	public function get_root_node() {
		return $this->root_node;
	}

	/**
	 * Set the root node.
	 *
	 * @param DOMElement $root_node The root node.
	 */
	public function set_root_node( $root_node ) {
		$this->root_node = $root_node;
	}

	/**
	 * Get destination.
	 *
	 * @return string
	 */
	public function get_response_destination() {
		return $this->response_destination;
	}

	/**
	 * Set destination.
	 *
	 * @param string $response_destination Destination.
	 */
	public function set_response_destination( $response_destination ) {
		$this->response_destination = $response_destination;
	}

	/**
	 * Get assertions.
	 *
	 * @return Assertions_DTO[]
	 */
	public function get_assertions() {
		return $this->assertions;
	}

	/**
	 * Set assertions.
	 *
	 * @param Assertions_DTO[] $assertions Assertions.
	 */
	public function set_assertions( $assertions ) {
		$this->assertions = $assertions;
	}

	/**
	 * Add assertion.
	 *
	 * @param Assertions_DTO $assertion Assertion.
	 */
	public function add_assertion( $assertion ) {
		$this->assertions[] = $assertion;
	}

	/**
	 * Get certificates.
	 *
	 * @return string|array
	 */
	public function get_certificates() {
		return $this->certificates;
	}

	/**
	 * Set certificates.
	 *
	 * @param string|array $certificates Certificates.
	 */
	public function set_certificates( $certificates ) {
		$this->certificates = $certificates;
	}

	/**
	 * Get signature node.
	 *
	 * @return string
	 */
	public function get_signature_node() {
		return $this->signature_node;
	}

	/**
	 * Set signature node.
	 *
	 * @param string $signature_node Signature node.
	 */
	public function set_signature_node( $signature_node ) {
		$this->signature_node = $signature_node;
	}

	/**
	 * Get the XML Security DSig object.
	 *
	 * @return XMLSecurityDSig
	 */
	public function get_xml_sec_dsig_obj() {
		return $this->xml_sec_dsig_obj;
	}

	/**
	 * Set the XML Security DSig object.
	 *
	 * @param XMLSecurityDSig $xml_sec_dsig_obj The XML Security DSig object.
	 */
	public function set_xml_sec_dsig_obj( $xml_sec_dsig_obj ) {
		$this->xml_sec_dsig_obj = $xml_sec_dsig_obj;
	}

	/**
	 * Get signature method.
	 *
	 * @return string
	 */
	public function get_signature_method() {
		return $this->signature_method;
	}

	/**
	 * Set signature method.
	 *
	 * @param string $signature_method Signature method.
	 */
	public function set_signature_method( $signature_method ) {
		$this->signature_method = $signature_method;
	}

	/**
	 * Get signature method algorithm.
	 *
	 * @return string
	 */
	public function get_signature_method_algorithm() {
		return $this->signature_method_algorithm;
	}

	/**
	 * Set signature method algorithm.
	 *
	 * @param string $signature_method_algorithm Signature method algorithm.
	 */
	public function set_signature_method_algorithm( $signature_method_algorithm ) {
		$this->signature_method_algorithm = $signature_method_algorithm;
	}

	/**
	 * Get issuer.
	 *
	 * @return string
	 */
	public function get_issuer() {
		return $this->issuer;
	}

	/**
	 * Set issuer.
	 *
	 * @param string $issuer Issuer.
	 */
	public function set_issuer( $issuer ) {
		$this->issuer = $issuer;
	}

	/**
	 * Get status code value.
	 *
	 * @return string
	 */
	public function get_status_code_value() {
		return $this->status_code_value;
	}

	/**
	 * Set status code value.
	 *
	 * @param string $status_code_value Status code.
	 */
	public function set_status_code_value( $status_code_value ) {
		$status_array            = explode( ':', $status_code_value );
		$this->status_code_value = ! empty( $status_array[7] ) ? $status_array[7] : '';
	}

	/**
	 * Get status message.
	 *
	 * @return string
	 */
	public function get_status_message() {
		return $this->status_message;
	}

	/**
	 * Set status message.
	 *
	 * @param string $status_message Status message.
	 */
	public function set_status_message( $status_message ) {
		$this->status_message = $status_message;
	}

	/**
	 * Get logout response.
	 *
	 * @return string
	 */
	public function get_logout_response() {
		return $this->logout_response;
	}

	/**
	 * Set logout response.
	 *
	 * @param string $logout_response Logout response.
	 */
	public function set_logout_response( $logout_response ) {
		$this->logout_response = $logout_response;
	}

	/**
	 * Get IdP Details.
	 *
	 * @return object
	 */
	public function get_idp_details() {
		return $this->idp_details;
	}

	/**
	 * Set IdP Details.
	 *
	 * @param object $idp_details IDP details object.
	 */
	public function set_idp_details( $idp_details ) {
		$this->idp_details = $idp_details;
	}

	/**
	 * Get SP Details.
	 *
	 * @return object
	 */
	public function get_sp_details() {
		return $this->sp_details;
	}

	/**
	 * Set SP Details.
	 *
	 * @param object $sp_details SP details object.
	 */
	public function set_sp_details( $sp_details ) {
		$this->sp_details = $sp_details;
	}
}
