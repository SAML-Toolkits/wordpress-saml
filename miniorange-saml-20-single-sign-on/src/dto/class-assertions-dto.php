<?php
/**
 * Assertions DTO.
 *
 * @package MOSAML\SRC\DTO
 */

namespace MOSAML\SRC\DTO;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\SRC\Utils\Utility;

/**
 * Data Transfer Object for SAML Assertions
 *
 * This class represents a SAML assertion and contains all the properties
 * that can be present in a SAML assertion, including subject, conditions,
 * attributes, and authentication context information.
 */
class Assertions_DTO {

	/**
	 * Root node.
	 *
	 * @var DOMElement
	 */
	private $root_node;

	/**
	 * Assertion ID.
	 *
	 * @var string
	 */
	private $assertion_id;

	/**
	 * Assertion Version.
	 *
	 * @var string
	 */
	private $assertion_version;

	/**
	 * Assertion Issue Instant.
	 *
	 * @var string
	 */
	private $assertion_issue_instant;

	/**
	 * Issuer.
	 *
	 * @var string
	 */
	private $issuer;

	/**
	 * Name ID.
	 *
	 * @var string
	 */
	private $name_id;

	/**
	 * Not Before.
	 *
	 * @var string
	 */
	private $conditions_not_before;

	/**
	 * Not On Or After.
	 *
	 * @var string
	 */
	private $conditions_not_on_or_after;

	/**
	 * Valid Audiences.
	 *
	 * @var array
	 */
	private $audiences;

	/**
	 * Session Not On Or After.
	 *
	 * @var string
	 */
	private $authn_statement_session_not_on_or_after;

	/**
	 * Authn Instant.
	 *
	 * @var string
	 */
	private $authn_statement_authn_instant;

	/**
	 * Authn Context Class Ref.
	 *
	 * @var string
	 */
	private $authn_context_class_ref;

	/**
	 * Authn Context Decl.
	 *
	 * @var string
	 */
	private $authn_context_decl;

	/**
	 * Authn Context Decl Ref.
	 *
	 * @var string
	 */
	private $authn_context_decl_ref;

	/**
	 * Session Index.
	 *
	 * @var string
	 */
	private $authn_statement_session_index;

	/**
	 * Attributes.
	 *
	 * @var string
	 */
	private $attributes;

	/**
	 * Name ID Format.
	 *
	 * @var string
	 */
	private $name_id_format;

	/**
	 * Signature Node.
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
	 * Signature Method.
	 *
	 * @var string
	 */
	private $signature_method;

	/**
	 * Signature Method Algorithm.
	 *
	 * @var string
	 */
	private $signature_method_algorithm;

	/**
	 * Certificates.
	 *
	 * @var string|array
	 */
	private $certificates;

	/**
	 * Wassignedatconstruction.
	 *
	 * @var string
	 */
	protected $wassignedatconstruction = false;

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
	 * Get the assertion ID.
	 *
	 * @return string
	 */
	public function get_assertion_id() {
		return $this->assertion_id;
	}

	/**
	 * Set the assertion ID.
	 *
	 * @param string $assertion_id The assertion ID.
	 */
	public function set_assertion_id( $assertion_id ) {
		$this->assertion_id = $assertion_id;
	}

	/**
	 * Get the assertion issue instant.
	 *
	 * @return string
	 */
	public function get_assertion_issue_instant() {
		return $this->assertion_issue_instant;
	}

	/**
	 * Set the assertion issue instant.
	 *
	 * @param string $assertion_issue_instant The assertion issue instant.
	 */
	public function set_assertion_issue_instant( $assertion_issue_instant ) {
		$assertion_issue_instant       = Utility::convert_date_time_to_timestamp( $assertion_issue_instant );
		$this->assertion_issue_instant = $assertion_issue_instant;
	}

	/**
	 * Get the assertion version.
	 *
	 * @return string
	 */
	public function get_assertion_version() {
		return $this->assertion_version;
	}

	/**
	 * Set the assertion version.
	 *
	 * @param string $assertion_version The assertion version.
	 */
	public function set_assertion_version( $assertion_version ) {
		$this->assertion_version = $assertion_version;
	}

	/**
	 * Get the issuer.
	 *
	 * @return string
	 */
	public function get_issuer() {
		return $this->issuer;
	}

	/**
	 * Set the issuer.
	 *
	 * @param string $issuer The issuer.
	 */
	public function set_issuer( $issuer ) {
		$this->issuer = $issuer;
	}

	/**
	 * Get the name ID.
	 *
	 * @return string
	 */
	public function get_name_id() {
		return $this->name_id;
	}

	/**
	 * Set the name ID.
	 *
	 * @param string $name_id The name ID.
	 */
	public function set_name_id( $name_id ) {
		$this->name_id = $name_id;
	}

	/**
	 * Set the encryption key.
	 *
	 * Get the conditions not before.
	 *
	 * @return string
	 */
	public function get_conditions_not_before() {
		return $this->conditions_not_before;
	}

	/**
	 * Set the conditions not before.
	 *
	 * @param string $conditions_not_before The conditions not before.
	 */
	public function set_conditions_not_before( $conditions_not_before ) {
		$conditions_not_before       = Utility::convert_date_time_to_timestamp( $conditions_not_before );
		$this->conditions_not_before = $conditions_not_before;
	}

	/**
	 * Get the conditions not on or after.
	 *
	 * @return string
	 */
	public function get_conditions_not_on_or_after() {
		return $this->conditions_not_on_or_after;
	}

	/**
	 * Set the conditions not on or after.
	 *
	 * @param string $conditions_not_on_or_after The conditions not on or after.
	 */
	public function set_conditions_not_on_or_after( $conditions_not_on_or_after ) {
		$conditions_not_on_or_after       = Utility::convert_date_time_to_timestamp( $conditions_not_on_or_after );
		$this->conditions_not_on_or_after = $conditions_not_on_or_after;
	}

	/**
	 * Get the audiences.
	 *
	 * @return array
	 */
	public function get_audiences() {
		return $this->audiences;
	}

	/**
	 * Set the audiences.
	 *
	 * @param array $audiences The audiences.
	 */
	public function set_audiences( $audiences ) {
		$this->audiences = $audiences;
	}

	/**
	 * Get the authn statement session not on or after.
	 *
	 * @return string
	 */
	public function get_authn_statement_session_not_on_or_after() {
		return $this->authn_statement_session_not_on_or_after;
	}

	/**
	 * Set the authn statement session not on or after.
	 *
	 * @param string $authn_statement_session_not_on_or_after The authn statement session not on or after.
	 */
	public function set_authn_statement_session_not_on_or_after( $authn_statement_session_not_on_or_after ) {
		$authn_statement_session_not_on_or_after       = Utility::convert_date_time_to_timestamp( $authn_statement_session_not_on_or_after );
		$this->authn_statement_session_not_on_or_after = $authn_statement_session_not_on_or_after;
	}

	/**
	 * Get the authn statement session index.
	 *
	 * @return string
	 */
	public function get_authn_statement_session_index() {
		return $this->authn_statement_session_index;
	}

	/**
	 * Set the authn statement session index.
	 *
	 * @param string $authn_statement_session_index The authn statement session index.
	 */
	public function set_authn_statement_session_index( $authn_statement_session_index ) {
		$this->authn_statement_session_index = $authn_statement_session_index;
	}

	/**
	 * Get the authn statement authn instant.
	 *
	 * @return string
	 */
	public function get_authn_statement_authn_instant() {
		return $this->authn_statement_authn_instant;
	}

	/**
	 * Set the authn statement authn instant.
	 *
	 * @param string $authn_statement_authn_instant The authn statement authn instant.
	 */
	public function set_authn_statement_authn_instant( $authn_statement_authn_instant ) {
		$authn_statement_authn_instant       = Utility::convert_date_time_to_timestamp( $authn_statement_authn_instant );
		$this->authn_statement_authn_instant = $authn_statement_authn_instant;
	}

	/**
	 * Get the authn context class ref.
	 *
	 * @return string
	 */
	public function get_authn_context_class_ref() {
		return $this->authn_context_class_ref;
	}

	/**
	 * Set the authn context class ref.
	 *
	 * @param string $authn_context_class_ref The authn context class ref.
	 */
	public function set_authn_context_class_ref( $authn_context_class_ref ) {
		$this->authn_context_class_ref = $authn_context_class_ref;
	}

	/**
	 * Get the authn context decl ref.
	 *
	 * @return string
	 */
	public function get_authn_context_decl_ref() {
		return $this->authn_context_decl_ref;
	}

	/**
	 * Set the authn context decl ref.
	 *
	 * @param string $authn_context_decl_ref The authn context decl ref.
	 */
	public function set_authn_context_decl_ref( $authn_context_decl_ref ) {
		$this->authn_context_decl_ref = $authn_context_decl_ref;
	}

	/**
	 * Get the authn context decl.
	 *
	 * @return string
	 */
	public function get_authn_context_decl() {
		return $this->authn_context_decl;
	}

	/**
	 * Set the authn context decl.
	 *
	 * @param string $authn_context_decl The authn context decl.
	 */
	public function set_authn_context_decl( $authn_context_decl ) {
		$this->authn_context_decl = $authn_context_decl;
	}

	/**
	 * Get the attributes.
	 *
	 * @return string
	 */
	public function get_attributes() {
		return $this->attributes;
	}

	/**
	 * Set the attributes.
	 *
	 * @param string $attributes The attributes.
	 */
	public function set_attributes( $attributes ) {
		$this->attributes = $attributes;
	}

	/**
	 * Get the name ID format.
	 *
	 * @return string
	 */
	public function get_name_id_format() {
		return $this->name_id_format;
	}

	/**
	 * Set the name ID format.
	 *
	 * @param string $name_id_format The name ID format.
	 */
	public function set_name_id_format( $name_id_format ) {
		$this->name_id_format = $name_id_format;
	}

	/**
	 * Get the signature node.
	 *
	 * @return string
	 */
	public function get_signature_node() {
		return $this->signature_node;
	}

	/**
	 * Set the signature node.
	 *
	 * @param string $signature_node The signature node.
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
	 * Get the signature method.
	 *
	 * @return string
	 */
	public function get_signature_method() {
		return $this->signature_method;
	}

	/**
	 * Set the signature method.
	 *
	 * @param string $signature_method The signature method.
	 */
	public function set_signature_method( $signature_method ) {
		$this->signature_method = $signature_method;
	}

	/**
	 * Get the signature method algorithm.
	 *
	 * @return string
	 */
	public function get_signature_method_algorithm() {
		return $this->signature_method_algorithm;
	}

	/**
	 * Set the signature method algorithm.
	 *
	 * @param string $signature_method_algorithm The signature method algorithm.
	 */
	public function set_signature_method_algorithm( $signature_method_algorithm ) {
		$this->signature_method_algorithm = $signature_method_algorithm;
	}

	/**
	 * Get the certificates.
	 *
	 * @return string|array
	 */
	public function get_certificates() {
		return $this->certificates;
	}

	/**
	 * Set the certificates.
	 *
	 * @param string|array $certificates The certificates.
	 */
	public function set_certificates( $certificates ) {
		$this->certificates = $certificates;
	}

	/**
	 * Get the wavedatconstruction.
	 *
	 * @return string
	 */
	public function get_wassignedatconstruction() {
		return $this->wassignedatconstruction;
	}

	/**
	 * Set the wavedatconstruction.
	 *
	 * @param string $wassignedatconstruction The wavedatconstruction.
	 */
	public function set_wassignedatconstruction( $wassignedatconstruction ) {
		$this->wassignedatconstruction = $wassignedatconstruction;
	}
}
