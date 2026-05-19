<?php
/**
 * SAML Request DTO.
 *
 * @package MOSAML\SRC\DTO
 */

namespace MOSAML\SRC\DTO;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\SRC\Utils\DB_Utils;
use MOSAML\SRC\Constant\Constants;

/**
 * SAML Request DTO.
 *
 * @package MOSAML\SRC\DTO
 */
class SAML_Request_DTO {

	/**
	 * ID.
	 *
	 * @var string
	 */
	private $request_id;

	/**
	 * Request destination.
	 *
	 * @var string
	 */
	private $request_destination;

	/**
	 * Request version.
	 *
	 * @var string
	 */
	private $request_version;

	/**
	 * Name ID.
	 *
	 * @var string
	 */
	private $name_id;

	/**
	 * Relay state.
	 *
	 * @var string
	 */
	private $relay_state;

	/**
	 * SAML request.
	 *
	 * @var string
	 */
	private $saml_request;

	/**
	 * Redirect.
	 *
	 * @var string
	 */
	private $redirect;

	/**
	 * IDP details.
	 *
	 * @var object
	 */
	private $idp_details;

	/**
	 * Name ID format.
	 *
	 * @var string
	 */
	private $name_id_format;

	/**
	 * SP details.
	 *
	 * @var object
	 */
	private $sp_details;

	/**
	 * SP certificates.
	 *
	 * @var object
	 */
	private $sp_certificates;

	/**
	 * Issuer.
	 *
	 * @var string
	 */
	private $issuer;

	/**
	 * Get the request ID.
	 *
	 * @return string
	 */
	public function get_request_id() {
		return $this->request_id;
	}

	/**
	 * Set the request ID.
	 *
	 * @param string $request_id The request ID.
	 * @return void
	 */
	public function set_request_id( $request_id ) {
		$this->request_id = $request_id;
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
	 * @return void
	 */
	public function set_issuer( $issuer ) {
		$this->issuer = $issuer;
	}
	/**
	 * Get the request destination.
	 *
	 * @return string
	 */
	public function get_request_destination() {
		return $this->request_destination;
	}

	/**
	 * Set the request destination.
	 *
	 * @param string $request_destination The request destination.
	 * @return void
	 */
	public function set_request_destination( $request_destination ) {
		$this->request_destination = $request_destination;
	}

	/**
	 * Get the request version.
	 *
	 * @return string
	 */
	public function get_request_version() {
		return $this->request_version;
	}

	/**
	 * Set the request version.
	 *
	 * @param string $request_version The request version.
	 * @return void
	 */
	public function set_request_version( $request_version ) {
		$this->request_version = $request_version;
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
	 * @return void
	 */
	public function set_name_id( $name_id ) {
		$this->name_id = $name_id;
	}

	/**
	 * Get the relay state.
	 *
	 * @return string
	 */
	public function get_relay_state() {
		return $this->relay_state;
	}

	/**
	 * Set the relay state.
	 *
	 * @param string $relay_state The relay state.
	 * @return void
	 */
	public function set_relay_state( $relay_state ) {
		$this->relay_state = $relay_state;
	}

	/**
	 * Get the SAML request.
	 *
	 * @return string
	 */
	public function get_saml_request() {
		return $this->saml_request;
	}

	/**
	 * Set the SAML request.
	 *
	 * @param string $saml_request The SAML request.
	 * @return void
	 */
	public function set_saml_request( $saml_request ) {
		$this->saml_request = $saml_request;
	}

	/**
	 * Get the redirect.
	 *
	 * @return string
	 */
	public function get_redirect() {
		return $this->redirect;
	}

	/**
	 * Set the redirect.
	 *
	 * @param string $redirect The redirect.
	 * @return void
	 */
	public function set_redirect( $redirect ) {
		$this->redirect = $redirect;
	}

	/**
	 * Get the IDP details.
	 *
	 * @return object
	 */
	public function get_idp_details() {
		return $this->idp_details;
	}

	/**
	 * Set the IDP details.
	 *
	 * @param object $idp_details The IDP details.
	 * @return void
	 */
	public function set_idp_details( $idp_details ) {
		$this->idp_details = $idp_details;
	}

	/**
	 * Get the SP details.
	 *
	 * @return object
	 */
	public function get_sp_details() {
		return $this->sp_details;
	}

	/**
	 * Set the SP details.
	 *
	 * @param object $sp_details The SP details.
	 * @return void
	 */
	public function set_sp_details( $sp_details ) {
		$this->sp_details = $sp_details;
	}

	/**
	 * Set the SP certificates.
	 *
	 * @param object $sp_certificates The SP certificates.
	 * @return void
	 */
	public function set_sp_certificates( $sp_certificates ) {
		$this->sp_certificates = $sp_certificates;
	}

	/**
	 * Get the SP certificates.
	 *
	 * @return object
	 */
	public function get_sp_certificates() {
		return $this->sp_certificates;
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
	 * @return void
	 */
	public function set_name_id_format( $name_id_format ) {
		$this->name_id_format = $name_id_format;
	}

	/**
	 * Save the DTO data to the database.
	 *
	 * @return bool True on success, false on failure.
	 */
	public function save() {
		return true;
	}

	/**
	 * Fetch data from the database and populate the DTO.
	 *
	 * @param array $where The where clause.
	 * @return void
	 */
	public function fetch( $where = array() ) {
		$where            = array_merge( $where, array( 'environment_id' => DB_Utils::get_environment_details( 'id' ) ) );
		$record           = DB_Utils::get_records( Constants::DATABASE_TABLE_NAMES['idp_details'], $where, true );
		$values_to_be_set = (array) $record;
		foreach ( $values_to_be_set as $column => $value ) {
			$method = 'set_' . $column;
			if ( property_exists( $this, $column ) ) {
				$this->$method( $value );
			}
		}
	}

	/**
	 * Get the table name.
	 *
	 * @return string
	 */
	public function get_table_name() {
		return Constants::DATABASE_TABLE_NAMES['idp_details'];
	}
}
