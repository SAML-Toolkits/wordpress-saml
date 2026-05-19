<?php
/**
 * Metadata Reader Class file.
 *
 * @package miniorange-saml-20-single-sign-on/src/class
 */

namespace MOSAML\SRC\Classes;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\SRC\Utils\Utility;
use MOSAML\Module\Base\Exception\Metadata_Upload_Exception;
use DOMElement;
use Exception;
use MOSAML\Module\Base\Exception\Metadata_Validation_Exception;
use MOSAML\SRC\Utils\DB_Utils;

/**
 * Metadata Reader Class.
 *
 * Handles parsing and reading of SAML metadata from XML files.
 * Provides functionality to extract entity descriptors, parse certificates,
 * and process various SAML metadata elements.
 *
 * @package miniorange-saml-20-single-sign-on/src/class
 */
class Metadata_Reader {

	/**
	 * Get entity descriptors from XML metadata.
	 *
	 * @param string $xml The XML metadata content.
	 * @return array Array of entity descriptors.
	 */
	public function get_entity_descriptors( $xml ) {
		$dom = Utility::safe_load_xml( $xml, 'metadata_reader' );
		if ( ! $dom ) {
			return array();
		}
		// phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- documentElement is a predefined DOM property.
		$entity_descriptors = Utility::xp_query( $dom->documentElement, './saml_metadata:EntitiesDescriptor' );

		if ( empty( $entity_descriptors ) ) {
			// phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- documentElement is a predefined DOM property.
			$entity_descriptors = Utility::xp_query( $dom->documentElement, './saml_metadata:EntityDescriptor' );

			// phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- documentElement is a predefined DOM property.
			if ( empty( $entity_descriptors ) && $dom->documentElement && 'EntityDescriptor' === $dom->documentElement->localName ) {
				// phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- documentElement is a predefined DOM property.
				$entity_descriptors = array( $dom->documentElement );
			}
		}
		return $entity_descriptors;
	}

	/**
	 * Read and parse metadata from entity descriptor.
	 *
	 * @param object     $data The data object to populate.
	 * @param DOMElement $entity_descriptor The entity descriptor element.
	 * @param array      $addition_details Additional configuration details.
	 * @return object The populated data object.
	 * @throws Metadata_Upload_Exception When metadata parsing fails.
	 */
	public function read_metadata( $data, $entity_descriptor, $addition_details = array() ) {
		try {
			return $this->parse_entity_descriptor( $entity_descriptor, $data, $addition_details );
		} catch ( Exception $e ) {
			throw new Metadata_Upload_Exception( 'Failed to parse metadata: ' . esc_html( $e->getMessage() ) );
		}
	}

	/**
	 * Parse entity descriptor and extract metadata.
	 *
	 * @param DOMElement $entity_descriptor The entity descriptor element.
	 * @param object     $data The data object to populate.
	 * @param array      $addition_details Additional configuration details.
	 * @return object The populated data object.
	 * @throws Metadata_Upload_Exception When required elements are missing.
	 */
	private function parse_entity_descriptor( DOMElement $entity_descriptor, $data, $addition_details = array() ) {
		$idp_sso_descriptors = Utility::xp_query( $entity_descriptor, './saml_metadata:IDPSSODescriptor' );
		if ( empty( $idp_sso_descriptors ) ) {
			if ( isset( $addition_details['multiple_idps'] ) && $addition_details['multiple_idps'] ) {
				return $data;
			}
			throw new Metadata_Upload_Exception( 'Missing required <IDPSSODescriptor> in <EntityDescriptor>.' );
		} elseif ( count( $idp_sso_descriptors ) > 1 ) {
			throw new Metadata_Upload_Exception( 'More than one <IDPSSODescriptor> in <EntityDescriptor>.' );
		}
		$idp_sso_descriptor = $idp_sso_descriptors[0];

		$sync_only_certificate = ! empty( $addition_details['sync_only_certificate'] );

		if ( ! $sync_only_certificate ) {
			$data = $this->parse_entity_id( $entity_descriptor, $data );
			$data = $this->parse_info( $idp_sso_descriptor, $data );
			$data = $this->parse_sso_service( $idp_sso_descriptor, $data );
			$data = $this->parse_name_id_format( $idp_sso_descriptor, $data );
			if ( isset( $addition_details['slo_service'] ) && $addition_details['slo_service'] ) {
				$data = $this->parse_slo_service( $idp_sso_descriptor, $data );
			}
			if ( isset( $addition_details['sign_request'] ) && $addition_details['sign_request'] ) {
				$data = $this->parse_sign_request( $idp_sso_descriptor, $data, true );
			} else {
				$data = $this->parse_sign_request( $idp_sso_descriptor, $data );
			}
			if ( empty( $data->idp_id ) ) {
				$data->idp_id = Utility::generate_idp_id();
			}
			if ( empty( $data->environment_id ) ) {
				$data->environment_id = DB_Utils::get_environment_details( 'id', false );
			}
			if ( empty( $data->status ) ) {
				$data->status = 'active';
			}
			if ( empty( $data->sp_entity_id ) ) {
				$data->sp_entity_id = DB_Utils::get_sp_details( 'sp_entity_id', false );
			}
		}
		$data = $this->parse_certificates( $idp_sso_descriptor, $data );
		return $data;
	}

	/**
	 * Parse entity ID from entity descriptor.
	 *
	 * @param DOMElement $entity_descriptor The entity descriptor element.
	 * @param object     $data The data object to populate.
	 * @return object The populated data object.
	 */
	private function parse_entity_id( $entity_descriptor, $data ) {
		if ( $entity_descriptor->hasAttribute( 'entityID' ) ) {
			$data->entity_id = $entity_descriptor->getAttribute( 'entityID' );
		}
		return $data;
	}

	/**
	 * Parse display information from IDP SSO descriptor.
	 *
	 * @param DOMElement $idp_sso_descriptor The IDP SSO descriptor element.
	 * @param object     $data The data object to populate.
	 * @return object The populated data object.
	 */
	private function parse_info( $idp_sso_descriptor, $data ) {
		$info = Utility::xp_query( $idp_sso_descriptor, './saml_metadata:Extensions' );
		if ( $info ) {
			$display_names = Utility::xp_query( $info[0], './mdui:UIInfo/mdui:DisplayName' );
			foreach ( $display_names as $name ) {
				if ( $name->hasAttribute( 'xml:lang' ) && $name->getAttribute( 'xml:lang' ) === 'en' ) {
					// phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- textContent is a predefined DOM property.
					$data->idp_name = $name->textContent;
					break;
				}
			}
		}
		return $data;
	}

	/**
	 * Parse SSO service information from IDP SSO descriptor.
	 *
	 * @param DOMElement $idp_sso_descriptor The IDP SSO descriptor element.
	 * @param object     $data The data object to populate.
	 * @return object The populated data object.
	 */
	private function parse_sso_service( $idp_sso_descriptor, $data ) {
		$sso_services = Utility::xp_query( $idp_sso_descriptor, './saml_metadata:SingleSignOnService' );
		if ( $sso_services ) {
			foreach ( $sso_services as $sso_service ) {
				$binding  = str_replace( 'urn:oasis:names:tc:SAML:2.0:bindings:', '', $sso_service->getAttribute( 'Binding' ) );
				$location = $sso_service->getAttribute( 'Location' );
				if ( ! empty( $binding ) && ! empty( $location ) ) {
					switch ( $binding ) {
						case 'HTTP-Redirect':
							$data->sso_url     = $location;
							$data->sso_binding = 'HttpRedirect';
							break 2;
						case 'HTTP-POST':
							$data->sso_url     = $location;
							$data->sso_binding = 'HttpPost';
							break;
						default:
							$data->sso_url     = $location;
							$data->sso_binding = 'HttpRedirect';
							break;
					}
				}
			}
		}
		return $data;
	}

	/**
	 * Parse name ID format from IDP SSO descriptor.
	 *
	 * @param DOMElement $idp_sso_descriptor The IDP SSO descriptor element.
	 * @param object     $data The data object to populate.
	 * @return object The populated data object.
	 */
	private function parse_name_id_format( $idp_sso_descriptor, $data ) {
		$name_ids = Utility::xp_query( $idp_sso_descriptor, './saml_metadata:NameIDFormat' );
		foreach ( $name_ids as $name_id ) {
			// phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- nodeValue is a predefined DOM property.
			$name_id_format       = str_replace( 'urn:oasis:names:tc:SAML:1.1:nameid-format:', '', $name_id->nodeValue );
			$data->name_id_format = $name_id_format;
		}
		if ( empty( $data->name_id_format ) ) {
			$data->name_id_format = 'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified';
		}
		return $data;
	}

	/**
	 * Parse certificates from IDP SSO descriptor.
	 *
	 * @param DOMElement $idp_sso_descriptor The IDP SSO descriptor element.
	 * @param object     $data The data object to populate.
	 * @param bool       $parse_encryption Whether to parse encryption certificates.
	 * @return object The populated data object.
	 * @throws Metadata_Validation_Exception When no signing certificates are found.
	 */
	private function parse_certificates( $idp_sso_descriptor, $data, $parse_encryption = false ) {
		$certificates = array();
		foreach ( Utility::xp_query( $idp_sso_descriptor, './saml_metadata:KeyDescriptor' ) as $key_descriptor_node ) {
			// BASE: Skip encryption certificates, only process signing.
			if ( $key_descriptor_node->hasAttribute( 'use' ) && 'encryption' === $key_descriptor_node->getAttribute( 'use' ) && ! $parse_encryption ) {
				continue;
			}
			$certificates = $this->extract_certificate( $key_descriptor_node, $certificates );
		}

		$data->idp_certificate = $certificates;
		return $data;
	}

	/**
	 * Extract certificate data from XML element.
	 *
	 * @param \DOMElement $xml The XML element containing certificate data.
	 * @param array       $certificates Array of existing certificates.
	 * @return array Array of certificates including the extracted one.
	 */
	private function extract_certificate( \DOMElement $xml, $certificates ) {
		$cert_node = Utility::xp_query( $xml, './ds:KeyInfo/ds:X509Data/ds:X509Certificate' );
		if ( ! empty( $cert_node ) ) {
			foreach ( $cert_node as $cert_node_value ) {
				// phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- nodeValue is a predefined DOM property.
				$node_value = $cert_node_value->nodeValue;
				if ( ! empty( $node_value ) ) {
					// phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- textContent is a predefined DOM property.
					$cert_data      = trim( $cert_node_value->textContent );
					$cert_data      = str_replace( array( "\r", "\n", "\t", ' ' ), '', $cert_data );
					$formatted_cert = '-----BEGIN CERTIFICATE-----' . "\n" . chunk_split( $cert_data, 64, "\n" ) . '-----END CERTIFICATE-----';
					array_push( $certificates, $formatted_cert );
				}
			}
		}
		return $certificates;
	}

	/**
	 * Parse SLO service information from IDP SSO descriptor.
	 *
	 * @param DOMElement $idp_sso_descriptor The IDP SSO descriptor element.
	 * @param object     $data The data object to populate.
	 * @return object The populated data object.
	 */
	private function parse_slo_service( $idp_sso_descriptor, $data ) {
		$slo_services = Utility::xp_query( $idp_sso_descriptor, './saml_metadata:SingleLogoutService' );
		foreach ( $slo_services as $slo_service ) {
			$binding           = str_replace( 'urn:oasis:names:tc:SAML:2.0:bindings:', '', $slo_service->getAttribute( 'Binding' ) );
			$location          = $slo_service->getAttribute( 'Location' );
			$response_location = $slo_service->getAttribute( 'ResponseLocation' );
			if ( ! empty( $binding ) && ! empty( $location ) ) {
				switch ( $binding ) {
					case 'HTTP-Redirect':
						$data->slo_url     = $location;
						$data->slo_binding = 'HttpRedirect';
						break 2;
					case 'HTTP-POST':
						$data->slo_url     = $location;
						$data->slo_binding = 'HttpPost';
						break;
					default:
						$data->slo_url     = $location;
						$data->slo_binding = 'HttpRedirect';
						break;
				}
			}
			if ( ! empty( $response_location ) ) {
				$data->slo_response_url = $response_location;
			}
		}
		return $data;
	}

	/**
	 * Parse sign request configuration from IDP SSO descriptor.
	 *
	 * @param DOMElement $idp_sso_descriptor The IDP SSO descriptor element.
	 * @param object     $data The data object to populate.
	 * @return object The populated data object.
	 */
	private function parse_sign_request( $idp_sso_descriptor, $data ) {
		if ( $idp_sso_descriptor->hasAttribute( 'WantAuthnRequestsSigned' ) ) {
			$wants_signed               = 'true' === strtolower( $idp_sso_descriptor->getAttribute( 'WantAuthnRequestsSigned' ) ) || '1' === $idp_sso_descriptor->getAttribute( 'WantAuthnRequestsSigned' );
			$data->sign_sso_slo_request = $wants_signed ? 'checked' : '';
		} else {
			$data->sign_sso_slo_request = '';
		}
		return $data;
	}
}
