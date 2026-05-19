<?php
/**
 * SAML Response Handler.
 *
 * @package MOSAML\Module\Base\Handler\SAML
 */

namespace MOSAML\Module\Base\Handler\SAML;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use DOMDocument;
use DOMElement;
use DOMXPath;
use MOSAML\SRC\Classes\Debug_Logger;
use MOSAML\SRC\DTO\SAML_Response_DTO;
use MOSAML\SRC\DTO\Assertions_DTO;
use MOSAML\SRC\Utils\Utility;
use MOSAML\SRC\Utils\Certificate_Utility;
use MOSAML\SRC\Utils\XML_Utility;
use RobRichards\XMLSecLibs\XMLSecurityKey;
use MOSAML\SRC\Constant\XML_Constants;
use RobRichards\XMLSecLibs\XMLSecurityDSig;
use MOSAML\SRC\Constant\Plugin_Options;
use MOSAML\SRC\Exception\Encrypted_Assertion_Exception;
use MOSAML\SRC\Exception\Invalid_Assertion_Exception;
use MOSAML\SRC\Exception\Signature_Not_Found_Exception;
use MOSAML\SRC\Exception\SP_Clock_Behind_Of_IDP_Clock_Exception;
use MOSAML\SRC\Exception\SP_Clock_Ahead_Of_IDP_Clock_Exception;
use MOSAML\SRC\Exception\Invalid_XML_Exception;
use MOSAML\SRC\Exception\Invalid_Status_Code_Exception;
use MOSAML\SRC\Exception\Cert_Mismatch_Exception;
use MOSAML\SRC\Exception\Cert_Mismatch_Encoding_Exception;
use MOSAML\SRC\Exception\IDP_Not_Present_At_SP_Exception;
use MOSAML\SRC\Exception\Invalid_Entity_ID_Exception;
use MOSAML\SRC\Exception\Invalid_Audience_URI_Exception;
use MOSAML\SRC\Exception\Duplicate_SAML_Response_Exception;
use MOSAML\SRC\Utils\DB_Utils;

/**
 * SAML Response Handler
 *
 * This class handles the basic parsing of SAML responses. It focuses on
 * extracting the response envelope and delegating assertion parsing to
 * the SAML_Assertion_Parser class.
 *
 * @package MOSAML\Module\Base\Handler
 */
class SAML_Response_Handler {

	/**
	 * SAML Response DTO instance
	 *
	 * @var SAML_Response_DTO
	 */
	public SAML_Response_DTO $dto;

	/**
	 * Assertions DTO instances
	 *
	 * @var Assertions_DTO
	 */
	public Assertions_DTO $current_assertion;

	/**
	 * XPath object for querying the SAML response
	 *
	 * @var DOMXPath
	 */
	public DOMXPath $xpath;

	/**
	 * DOM document containing the SAML response
	 *
	 * @var DOMDocument
	 */
	public DOMDocument $document;

	/**
	 * Handle the SAML response.
	 *
	 * @param SAML_Response_DTO $saml_response_dto The SAML response DTO.
	 * @param string            $saml_response The SAML response.
	 * @return void
	 * @throws Invalid_Entity_ID_Exception If the issuer is invalid.
	 * @throws IDP_Not_Present_At_SP_Exception If IDP with issuer is not present at SP.
	 */
	public function handle_saml_response( SAML_Response_DTO $saml_response_dto, string $saml_response ) {
		$this->dto = $saml_response_dto;
		$this->decode_and_load_saml_response( $saml_response );
		$this->set_response_dto();

		$root           = $this->dto->get_root_node();
		$response_id    = $root instanceof DOMElement ? $root->getAttribute( 'ID' ) : '';
		$in_response_to = $root instanceof DOMElement ? $root->getAttribute( 'InResponseTo' ) : '';
		$receipt_log    = '[SAML Response] Received with ID: ' . $response_id . ', InResponseTo: ' . $in_response_to;
		Debug_Logger::log( $receipt_log );

		$idp_issuer  = ! empty( $this->dto->get_issuer() ) ? $this->dto->get_issuer() : $this->current_assertion->get_issuer();
		$sp_details  = ( Utility::get_handler_object( 'sp_endpoints_data', true, 'admin' ) )->get_data( array( 'environment_id' => DB_Utils::get_environment_details( 'id' ) ) );
		$idp_details = ( Utility::get_handler_object( 'sp_setup_data', true, 'admin' ) )->get_data(
			array(
				'entity_id'      => $idp_issuer,
				'environment_id' => DB_Utils::get_environment_details( 'id' ),
			)
		);
		if ( ! $this->dto->get_logout_response() ) {

			if ( empty( $idp_details->entity_id ) ) {
				if ( session_status() === PHP_SESSION_NONE ) {
					session_start();
				}
				// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Session value sanitized and unslashed.
				$idp_id_in_session = isset( $_SESSION['mosaml_login_idp_id'] ) ? sanitize_text_field( wp_unslash( $_SESSION['mosaml_login_idp_id'] ) ) : '';
				if ( ! empty( $idp_id_in_session ) ) {
					$idp_details_in_session = ( Utility::get_handler_object( 'sp_setup_data', true, 'admin' ) )->get_data(
						array(
							'idp_id'         => $idp_id_in_session,
							'environment_id' => DB_Utils::get_environment_details( 'id' ),
						)
					);
				}
				if ( ! empty( $idp_details_in_session->entity_id ) ) {
					$details = array(
						'to_update' => array(
							'idp_id'    => $idp_details_in_session->idp_id,
							'entity_id' => $idp_issuer,
						),
						'to_show'   => array(
							'Entity ID Received in SAML Response' => $idp_issuer,
						),
					);
					throw new Invalid_Entity_ID_Exception( wp_json_encode( $details ) );
				}
				throw new IDP_Not_Present_At_SP_Exception( 'IDP with Issuer "' . esc_html( $idp_issuer ) . '" not found.' );
			}

			// phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- Public integration hook.
			$idp_details_secondary = apply_filters( 'mosaml_filter_identity_providers_internal', array(), $saml_response_dto );
			if ( ! empty( $identity_provider ) && is_array( $identity_provider ) ) {
					$idp_details->entity_id       = $idp_details_secondary['issuer'];
					$idp_details->idp_certificate = maybe_unserialize( $idp_details_secondary['certFromPlugin'] );
			}
			$this->dto->set_sp_details( $sp_details );
			$this->dto->set_idp_details( $idp_details );
			$this->dto->set_idp_pk( $idp_details->id );

			// Check for duplicate/replay attack before validation.
			$this->check_saml_response_for_replay_attack();

			$issuer             = ! empty( $this->dto->get_issuer() ) ? $this->dto->get_issuer() : $this->current_assertion->get_issuer();
			$subject            = $this->current_assertion->get_name_id();
			$issuer_subject_log = '[SAML Response] Issuer: ' . $issuer . ', Subject: ' . $subject;
			Debug_Logger::log( $issuer_subject_log );

			$this->validate_response();
			$sign_log = '[SAML Response] Signature validation: SUCCESS';
			Debug_Logger::log( $sign_log );

			$attributes = $this->current_assertion->get_attributes();
			$attr_pairs = array();
			if ( is_array( $attributes ) ) {
				foreach ( $attributes as $k => $v ) {
					$attr_pairs[] = $k . ': ' . ( is_array( $v ) ? implode( ',', $v ) : $v );
				}
			}
			Debug_Logger::log( '[SAML Response] Attributes:' . wp_json_encode( $attr_pairs, true ) );
		}
	}

	/**
	 * Decode and load the SAML response.
	 *
	 * @param string $saml_response The SAML response.
	 * @return void
	 * @throws Invalid_XML_Exception If the SAML response is invalid.
	 */
	public function decode_and_load_saml_response( string $saml_response ) {

		if ( empty( $saml_response ) ) {
			throw new Invalid_XML_Exception( 'Empty SAML response received' );
		}

		$decoded_response = XML_Utility::validate_compressed_xml( $saml_response, Plugin_Options::SAML_RESPONSE_OPTION['SAML_RESPONSE'] );

		$this->document = XML_Utility::safe_load_xml( $decoded_response );
		$this->xpath    = new DOMXPath( $this->document );

		foreach ( XML_Constants::RESPONSE_NAMESPACES as $prefix => $uri ) {
			$this->xpath->registerNamespace( $prefix, $uri );
		}
	}

	/**
	 * Parse the login response.
	 *
	 * @return void
	 * @throws Invalid_XML_Exception If the SAML response is invalid.
	 */
	public function set_response_dto() {

		$response_node = $this->xpath->query( './samlp:Response', $this->document );
		if ( 1 !== $response_node->length ) {
			throw new Invalid_XML_Exception( 'Invalid SAML response.' );
		}
		$response_node_item = $response_node->item( 0 );
		$this->dto->set_root_node( $response_node_item );

		XML_Utility::validate_and_set_nodes( $this, $response_node_item, $this->dto, XML_Constants::NODES_QUERY_MAP['response'] );

		$this->set_assertions_in_response_dto( $response_node_item );
	}

	/**
	 * Set the assertions in the response DTO.
	 *
	 * @param DOMElement $response_node The response node.
	 * @return void
	 * @throws Invalid_Assertion_Exception If the assertions are not found in the SAML response.
	 * @throws Encrypted_Assertion_Exception If the assertions are encrypted.
	 */
	public function set_assertions_in_response_dto( DOMElement $response_node ) {

		$assertion_nodes = $this->get_assertion_nodes_from_response( $response_node );

		foreach ( $assertion_nodes as $assertion_node ) {

			$assertions_dto = new Assertions_DTO();
			$assertions_dto->set_root_node( $assertion_node );
			XML_Utility::validate_and_set_nodes( $this, $assertion_node, $assertions_dto, XML_Constants::NODES_QUERY_MAP['assertion'] );

			$this->parse_and_set_attributes( $assertions_dto, $assertion_node );

			$assertions[] = $assertions_dto;
		}

		$this->dto->set_assertions( $assertions );
		$this->current_assertion = $assertions[0];
	}

	/**
	 * Get the assertion nodes from the response. Throws exception if no or encrypted assertion is found.
	 *
	 * @param DOMElement $response_node The response node.
	 * @return DOMNodeList
	 * @throws Encrypted_Assertion_Exception If encrypted assertion is found.
	 * @throws Invalid_Assertion_Exception If no assertion is found.
	 */
	public function get_assertion_nodes_from_response( DOMElement $response_node ) {
		$assertion_nodes = XML_Utility::get_list_items_as_array( $this->xpath->query( './saml:Assertion', $response_node ) );
		if ( empty( $assertion_nodes ) ) {
			$encrypted_assertions = XML_Utility::get_list_items_as_array( $this->xpath->query( './saml:EncryptedAssertion', $response_node ) );
			if ( ! empty( $encrypted_assertions ) ) {
				throw new Encrypted_Assertion_Exception( 'Encrypted assertions are not supported.' );
			}
			throw new Invalid_Assertion_Exception( 'No assertions found in SAML response.' );
		}
		return $assertion_nodes;
	}

	/**
	 * Parse and set attributes.
	 *
	 * @param Assertions_DTO $assertions_dto The assertions DTO.
	 * @param DOMElement     $assertion_node The assertion node.
	 * @return void
	 */
	public function parse_and_set_attributes( Assertions_DTO $assertions_dto, DOMElement $assertion_node ) {

		$attributes_arr  = array();
		$attribute_nodes = $this->xpath->query( './saml:AttributeStatement/saml:Attribute', $assertion_node );
		foreach ( $attribute_nodes as $attribute_node ) {
			if ( $attribute_node instanceof DOMElement ) {
				$attribute_name = $attribute_node->getAttribute( 'Name' );
				if ( ! empty( $attribute_name ) ) {
					$value_nodes                       = $this->xpath->query( './saml:AttributeValue', $attribute_node );
					$attributes_arr[ $attribute_name ] = XML_Utility::get_node_text_content( $value_nodes );
				}
			}
		}
		$assertions_dto->set_attributes( $attributes_arr );
	}

	/**
	 * Validate the status code value.
	 *
	 * @param SAML_Response_DTO $dto The DTO object.
	 * @return void
	 * @throws Invalid_Status_Code_Exception If the status code is not Success.
	 */
	public function validate_status( SAML_Response_DTO $dto ) {
		if ( 'Success' !== $dto->get_status_code_value() ) {
			throw new Invalid_Status_Code_Exception( 'Invalid status code in SAML response.' );
		}
	}

	/**
	 * Function to validate the assertion version.
	 *
	 * @param Assertions_DTO $dto The DTO object.
	 * @return void
	 * @throws Invalid_Assertion_Exception If the version is not supported.
	 */
	public function validate_version( Assertions_DTO $dto ) {
		if ( '2.0' !== $dto->get_assertion_version() ) {
			throw new Invalid_Assertion_Exception( 'Unsupported Version : ' . esc_html( $dto->get_assertion_version() ) );
		}
	}

	/**
	 * Validate the signature element.
	 *
	 * @param SAML_Response_DTO|Assertions_DTO $dto The DTO object.
	 * @return void
	 * @throws Invalid_Assertion_Exception If the signature element is not found in the SAML response.
	 */
	public function validate_signature_element( $dto ) {
		$obj_xml_sec_dsig = new XMLSecurityDSig();

		// Both SAML messages and SAML assertions use the 'ID' attribute.
		// phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- Can not convert into Snakecase, since it is a part of XMLSecurityDSig class.
		$obj_xml_sec_dsig->idKeys[] = 'ID';

		// phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- Can not convert into Snakecase, since it is a part of XMLSecurityDSig class.
		$obj_xml_sec_dsig->sigNode = $dto->get_signature_node();

		// Canonicalize the XMLDSig SignedInfo element in the message.
		$obj_xml_sec_dsig->canonicalizeSignedInfo();
		// Validate referenced xml nodes.
		if ( ! $obj_xml_sec_dsig->validateReference() ) {
			throw new Invalid_Assertion_Exception( 'XMLSec: digest validation failed.' );
		}

		// Check that $root is one of the signed nodes.
		$root_signed = false;
		foreach ( $obj_xml_sec_dsig->getValidatedNodes() as $signed_node ) {
			if ( $signed_node->isSameNode( $dto->get_root_node() ) ) {
				$root_signed = true;
				break;
				//phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- Can not convert into Snakecase, since it is a part of DOMElement class.
			} elseif ( $dto->get_root_node()->parentNode instanceof DOMDocument && $signed_node->isSameNode( $dto->get_root_node()->ownerDocument ) ) {
				// $root is the root element of a signed document.
				$root_signed = true;
				break;
			}
		}

		if ( ! $root_signed ) {
			throw new Invalid_Assertion_Exception( 'XMLSec: The root element is not signed.' );
		}

		$this->dto->set_xml_sec_dsig_obj( $obj_xml_sec_dsig );
	}

	/**
	 * Validate the response.
	 *
	 * @return void
	 */
	public function validate_response() {
		$this->validate_time_constraints();
		$this->validate_destination();
		$this->validate_signature_and_certificate();
		$this->validate_issuer_and_audience();
	}

	/**
	 * Validate the time constraints.
	 *
	 * @return void
	 * @throws SP_Clock_Behind_Of_IDP_Clock_Exception If the clock is behind the IDP clock.
	 * @throws SP_Clock_Ahead_Of_IDP_Clock_Exception If the clock is ahead of the IDP clock.
	 */
	public function validate_time_constraints() {

		if ( 'checked' !== $this->dto->get_idp_details()->assertion_time_validity ) {
			return;
		}

		$details = array(
			'to_update' => array(
				'idp_id'                  => $this->dto->get_idp_details()->idp_id,
				'assertion_time_validity' => '',
			),
		);

		if ( null !== $this->current_assertion->get_conditions_not_before() && $this->current_assertion->get_conditions_not_before() > time() + 60 ) {
			throw new SP_Clock_Behind_Of_IDP_Clock_Exception( wp_json_encode( $details ) );
		}

		if ( null !== $this->current_assertion->get_conditions_not_on_or_after() && $this->current_assertion->get_conditions_not_on_or_after() <= time() - 60 ) {
			throw new SP_Clock_Ahead_Of_IDP_Clock_Exception( wp_json_encode( $details ) );
		}

		if ( null !== $this->current_assertion->get_authn_statement_session_not_on_or_after() && $this->current_assertion->get_authn_statement_session_not_on_or_after() <= time() - 60 ) {
			throw new SP_Clock_Ahead_Of_IDP_Clock_Exception( wp_json_encode( $details ) );
		}
	}

	/**
	 * Validate the destination.
	 *
	 * @return void
	 * @throws Invalid_Assertion_Exception If the destination is invalid.
	 */
	public function validate_destination() {
		$acs_url              = ! empty( $this->dto->get_sp_details()->sp_base_url ) ? $this->dto->get_sp_details()->sp_base_url : site_url();
		$response_destination = $this->dto->get_response_destination();

		$query_pos = strpos( $response_destination, '?' );
		if ( false !== $query_pos ) {
			$response_destination = substr( $response_destination, 0, $query_pos );
		}
		if ( substr( $response_destination, -1 ) === '/' ) {
			$response_destination = substr( $response_destination, 0, -1 );
		}
		if ( substr( $acs_url, -1 ) === '/' ) {
			$acs_url = substr( $acs_url, 0, -1 );
		}

		if ( $acs_url !== $response_destination ) {
			throw new Invalid_Assertion_Exception( 'Destination in response doesn\'t match the current URL. Destination is "' . esc_url_raw( $response_destination ) . '", current URL is "' . esc_url_raw( $acs_url ) . '".' );
		}
	}

	/**
	 * Validate the signature.
	 *
	 * @return void
	 * @throws Signature_Not_Found_Exception If the signature is not found.
	 */
	public function validate_signature_and_certificate() {

		if ( empty( $this->dto->get_signature_node() ) && empty( $this->current_assertion->get_signature_node() ) ) {
			throw new Signature_Not_Found_Exception( 'No signature was found in the SAML Response or Assertion.' );
		}
		$idp_certificates = maybe_unserialize( $this->dto->get_idp_details()->idp_certificate );

		$is_signature_valid = false;
		if ( is_array( $idp_certificates ) ) {
			foreach ( $idp_certificates as $key => $idp_certificate ) {
				$idp_certificate_thumbprint = $this->process_certificate_thumbprint( $idp_certificate );

				if ( ! empty( $this->dto->get_signature_node() ) ) {
					$is_signature_valid = $this->verify_signature( $this->dto, $idp_certificate_thumbprint, $idp_certificate );
				}
				if ( ! empty( $this->current_assertion->get_signature_node() ) ) {
					$is_signature_valid = $this->verify_signature( $this->current_assertion, $idp_certificate_thumbprint, $idp_certificate );
				}
				if ( $is_signature_valid ) {
					break;
				}
			}
		} else {
			$idp_certificate_thumbprint = $this->process_certificate_thumbprint( $idp_certificates );
			if ( ! empty( $this->dto->get_signature_node() ) ) {
				$is_signature_valid = $this->verify_signature( $this->dto, $idp_certificate_thumbprint, $idp_certificates );
			}
			if ( ! empty( $this->current_assertion->get_signature_node() ) ) {
				$is_signature_valid = $this->verify_signature( $this->current_assertion, $idp_certificate_thumbprint, $idp_certificates );
			}
		}

		if ( ! $is_signature_valid ) {
			$this->validate_certificate();
		}
	}

	/**
	 * This function checks if the certificate is valid. If not, it will throw an exception as per the condition.
	 *
	 * @return void
	 * @throws Cert_Mismatch_Exception If the certificate is invalid.
	 * @throws Cert_Mismatch_Encoding_Exception If the certificate is invalid because of encoding.
	 */
	public function validate_certificate() {
		$saml_response_certificate = ! empty( $this->dto->get_certificates() ) ? $this->dto->get_certificates() : $this->current_assertion->get_certificates();
		$saml_response_certificate = is_array( $saml_response_certificate ) ? $saml_response_certificate[0] : $saml_response_certificate;
		$idp_certificates          = maybe_unserialize( $this->dto->get_idp_details()->idp_certificate );

		$is_certificate_valid = false;
		if ( is_array( $idp_certificates ) ) {
			foreach ( $idp_certificates as $idp_certificate ) {
				$desanitized_idp_certificate = Certificate_Utility::desanitize_certificate( $idp_certificate );
				if ( $desanitized_idp_certificate === $saml_response_certificate ) {
					$is_certificate_valid = true;
					break;
				}
			}
		} else {
			$desanitized_idp_certificate = Certificate_Utility::desanitize_certificate( $idp_certificates );
			if ( $desanitized_idp_certificate === $saml_response_certificate ) {
				$is_certificate_valid = true;
			}
		}
		if ( ! $is_certificate_valid ) {
			$saml_response_certificate = '-----BEGIN CERTIFICATE-----' . "\n" . chunk_split( preg_replace( '/\s+/', '', $saml_response_certificate ), 64, "\n" ) . '-----END CERTIFICATE-----';

			$details = array(
				'to_update' => array(
					'idp_id'          => $this->dto->get_idp_details()->idp_id,
					'idp_certificate' => $saml_response_certificate,
				),
				'to_show'   => array(
					'Certificate Received in SAML Response' => $saml_response_certificate,
				),
			);
			throw new Cert_Mismatch_Exception( wp_json_encode( $details ) );
		} elseif ( 'checked' === $this->dto->get_idp_details()->character_encoding ) {
			$details = array(
				'to_update' => array(
					'idp_id'             => $this->dto->get_idp_details()->idp_id,
					'character_encoding' => '',
				),
			);
			throw new Cert_Mismatch_Encoding_Exception( wp_json_encode( $details ) );
		}
	}

	/**
	 * Process the certificate thumbprint.
	 *
	 * @param string $idp_certificate The IDP certificate.
	 * @return string The IDP certificate.
	 */
	public function process_certificate_thumbprint( string $idp_certificate ) {
		$idp_certificate_thumbprint = XMLSecurityKey::getRawThumbprint( $idp_certificate );
		if ( ! empty( $idp_certificate_thumbprint ) ) {
			$idp_certificate_thumbprint = $this->convert_to_windows_iconv( $idp_certificate_thumbprint );
			$idp_certificate_thumbprint = preg_replace( '/\s+/', '', $idp_certificate_thumbprint );
		}
		return $idp_certificate_thumbprint;
	}

	/**
	 * Convert to windows iconv.
	 *
	 * @param string $idp_certificate_thumbprint The IDP certificate thumbprint.
	 * @return string
	 */
	public function convert_to_windows_iconv( string $idp_certificate_thumbprint ) {

		if ( 'checked' === $this->dto->get_idp_details()->character_encoding && XML_Utility::is_iconv_installed() ) {
            // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Used to suppress iconv warning.
			return @iconv( XML_Constants::ENCODING_UTF_8, XML_Constants::ENCODING_CP1252, $idp_certificate_thumbprint );
		}

		return $idp_certificate_thumbprint;
	}

	/**
	 * Verify the signature.
	 *
	 * @param SAML_Response_DTO|Assertions_DTO $dto The DTO object.
	 * @param string                           $idp_certificate_thumbprint The IDP certificate thumbprint.
	 * @param string                           $idp_certificate The IDP certificate.
	 * @return bool
	 * @throws Invalid_Assertion_Exception If the signature is invalid.
	 */
	public function verify_signature( $dto, $idp_certificate_thumbprint, $idp_certificate ) {

		$response_certificates = $dto->get_certificates();

		if ( ! empty( $response_certificates ) ) {
			if ( is_array( $response_certificates ) ) {
				foreach ( $response_certificates as $response_certificate ) {
					$response_certificate = Certificate_Utility::desanitize_certificate( $response_certificate );
					$pem                  = $this->find_certificate( $response_certificate, $idp_certificate_thumbprint );
					if ( $pem ) {
						break;
					}
				}
			} else {
				$response_certificates = Certificate_Utility::desanitize_certificate( $response_certificates );
				$pem                   = $this->find_certificate( $response_certificates, $idp_certificate_thumbprint );
			}
		} else {
			$pem = $idp_certificate;
		}

		if ( ! $pem ) {
			return false;
		}

		$key = new XMLSecurityKey( XMLSecurityKey::RSA_SHA1, array( 'type' => 'public' ) );
		$key->loadKey( $pem );

		$signature_method_algorithm = $dto->get_signature_method_algorithm();
		$new_key                    = $key;

		if ( XMLSecurityKey::RSA_SHA1 === $key->type && $signature_method_algorithm !== $key->type ) {
			$key_info = openssl_pkey_get_details( $key->key );
			if ( false === $key_info ) {
				throw new Invalid_Assertion_Exception( 'Unable to get key details from XMLSecurityKey.' );
			}
			if ( ! isset( $key_info['key'] ) ) {
				throw new Invalid_Assertion_Exception( 'Missing key in public key details.' );
			}

			$new_key = new XMLSecurityKey( $signature_method_algorithm, array( 'type' => 'public' ) );
			$new_key->loadKey( $key_info['key'] );
		}

		if ( ! $this->dto->get_xml_sec_dsig_obj()->verify( $new_key ) ) {
			throw new Invalid_Assertion_Exception( 'Unable to validate signature.' );
		}

		return true;
	}

	/**
	 * Find the certificate.
	 *
	 * @param string $certificate The certificate.
	 * @param string $certificate_thumbprint The certificate thumbprint.
	 * @return string|false
	 */
	public function find_certificate( $certificate, $certificate_thumbprint ) {
		//phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_decode -- Required to decode the encoded certificates.
		$fp = strtolower( sha1( base64_decode( $certificate ) ) );
		if ( $fp === $certificate_thumbprint ) {

			/* We have found a matching fingerprint. */
			$pem = "-----BEGIN CERTIFICATE-----\n" .
				chunk_split( $certificate, 64 ) .
				"-----END CERTIFICATE-----\n";

			return $pem;
		} else {
			$candidates[] = $fp;
			return false;
		}
	}

	/**
	 * Validate the issuer and audience.
	 *
	 * @return void
	 * @throws Invalid_Audience_URI_Exception If the audience is invalid.
	 */
	public function validate_issuer_and_audience() {
		$audiences = $this->current_assertion->get_audiences();

		if ( ! empty( $this->dto->get_idp_details()->sp_entity_id ) ) {
			$sp_entity_id = $this->dto->get_idp_details()->sp_entity_id;
		} elseif ( ! empty( $this->dto->get_sp_details()->sp_entity_id ) ) {
			$sp_entity_id = $this->dto->get_sp_details()->sp_entity_id;
		} else {
			$sp_entity_id = site_url() . '/wp-content/plugins/miniorange-saml-20-single-sign-on/';
		}

		if ( ! empty( $audiences ) ) {
			$is_valid_audience = false;
			if ( is_array( $audiences ) && in_array( $sp_entity_id, $audiences, true ) ) {
				$is_valid_audience = true;
			} elseif ( $audiences === $sp_entity_id ) {
				$is_valid_audience = true;
			}

			if ( ! $is_valid_audience ) {
				if ( session_status() === PHP_SESSION_NONE ) {
					session_start();
				}

				$idp_id_in_session = isset( $_SESSION['mosaml_login_idp_id'] ) ? sanitize_text_field( wp_unslash( $_SESSION['mosaml_login_idp_id'] ) ) : '';

				if ( ! empty( $idp_id_in_session ) ) {
					$idp_details_in_session = ( Utility::get_handler_object( 'sp_setup_data', true, 'admin' ) )->get_data(
						array(
							'idp_id'         => $idp_id_in_session,
							'environment_id' => DB_Utils::get_environment_details( 'id' ),
						)
					);
				}

				if ( ! empty( $idp_details_in_session ) ) {
					$details = array(
						'to_update' => array(
							'idp_id'       => $idp_details_in_session->idp_id,
							'sp_entity_id' => $audiences,
						),
						'to_show'   => array(
							'SP Entity ID Received in SAML Response' => $audiences,
						),
					);
					throw new Invalid_Audience_URI_Exception( wp_json_encode( $details ) );
				}

				throw new Invalid_Audience_URI_Exception( 'Invalid audience in SAML response.' );
			}
		} else {
			throw new Invalid_Audience_URI_Exception( 'No audience found in SAML response.' );
		}
	}

	/**
	 * Check if SAML response is a duplicate/replay attack.
	 *
	 * This function checks if the SAML response has been processed before by checking
	 * if the assertion ID exists in transients. This prevents replay attacks where
	 * an attacker tries to reuse a valid SAML response.
	 *
	 * This function can also throw an error when user refresh/reload pages after saml
	 * response is processed by this function and authentication cookies not created.
	 *
	 * @return void
	 * @throws Duplicate_SAML_Response_Exception If a duplicate SAML response is detected.
	 */
	private function check_saml_response_for_replay_attack() {
		/**
		* Filter hook to skip the duplicate/replay attack check.
		 *
		 * Use this filter to disable this middleware check if needed.
		 * This can be useful in development or when dealing with IDPs that reuse assertion IDs.
		 *
		 * @param bool $skip_check Whether to skip the duplicate response check. Default false.
		 * @return bool True to skip the check, false to perform it.
		 */
		$skip_check = apply_filters( 'mosaml_skip_check_saml_response_for_replay_attack_internal', false );
		$skip_check = apply_filters( 'mosaml_skip_check_saml_response_for_reply_attack_internal', false );

		if ( $skip_check ) {
			return;
		}

		$assertion_id = $this->current_assertion->get_assertion_id();
		if ( empty( $assertion_id ) ) {
			// If assertion ID is not available, we cannot check for duplicates.
			return;
		}

		// Calculate expiry time based on NotOnOrAfter if available, otherwise use default.
		$not_on_or_after = $this->current_assertion->get_conditions_not_on_or_after();
		if ( null !== $not_on_or_after ) {
			$expiry = ( $not_on_or_after - time() ) + 300; // Add 5 minutes buffer.
		} else {
			$expiry = 15 * MINUTE_IN_SECONDS; // Default 15 minutes.
		}

		// Check if this assertion ID has been seen before.
		$transient_key      = 'mo_saml_assertion_' . $assertion_id;
		$existing_assertion = get_transient( $transient_key );
		if ( false !== $existing_assertion ) {
			// Duplicate response detected - throw exception.
			throw new Duplicate_SAML_Response_Exception( 'Duplicate SAML Response.' );
		}

		// Store the assertion ID in transient to prevent reuse.
		set_transient( $transient_key, 'existed', $expiry );
	}
}
