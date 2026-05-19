<?php
/**
 * XML Utility for safe XML processing.
 *
 * @package MOSAML\SRC\Utils
 */

namespace MOSAML\SRC\Utils;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use DOMDocument;
use DOMElement;
use Exception;
use DOMNodeList;
use RobRichards\XMLSecLibs\XMLSecurityKey;
use RobRichards\XMLSecLibs\XMLSecurityDSig;
use MOSAML\SRC\Constant\XML_Constants;
use MOSAML\Module\Base\Handler\SAML\SAML_Response_Handler;
use MOSAML\SRC\DTO\SAML_Response_DTO;
use MOSAML\SRC\DTO\Assertions_DTO;
use MOSAML\SRC\Exception\DOM_Extension_Disabled_Exception;
use MOSAML\SRC\Exception\Invalid_XML_Exception;
use MOSAML\SRC\Exception\Invalid_Assertion_Exception;
use MOSAML\SRC\DTO\SAML_Request_DTO;
use MOSAML\Module\Base\Handler\SAML\SAML_Request_Handler;
use MOSAML\SRC\Constant\Error_Codes_Enums;
/**
 * XML Utility class for safe XML processing.
 *
 * Provides methods for safely loading and processing XML documents
 * with security considerations for SAML processing.
 */
class XML_Utility {

	/**
	 * Handle XML errors during processing.
	 *
	 * @param int    $error_number Error number.
	 * @param string $error_message Error message.
	 * @param string $error_file Error file.
	 * @param int    $error_line Error line.
	 * @return bool|void
	 * @throws Invalid_XML_Exception If the XML is invalid.
	 */
	public static function handle_xml_error( $error_number, $error_message, $error_file, $error_line ) {
		unset( $error_file, $error_line );
		if ( E_WARNING === $error_number && ( substr_count( $error_message, 'DOMDocument::loadXML()' ) > 0 ) ) {
			// Log the warning when debug framework is implemented.
			throw new Invalid_XML_Exception( 'Invalid XML Detected.' );
		} else {
			return false;
		}
	}

	/**
	 * Safely load XML document with security considerations.
	 *
	 * @param string $xml XML string to load.
	 * @return DOMDocument
	 * @throws DOM_Extension_Disabled_Exception If DOMDocument is not available.
	 * @throws Invalid_XML_Exception If the XML is invalid.
	 */
	public static function safe_load_xml( $xml ) {

		if ( ! class_exists( 'DOMDocument' ) ) {
			throw new DOM_Extension_Disabled_Exception( 'DOMDocument Not Installed.' );
		}
		$document = new DOMDocument();
		libxml_set_external_entity_loader( null );
		// Loading XML will not expand internal entities. These option don't provide any safety against internal entities expansion or recursive internal expansion. LIBXML_DTDLOAD | LIBXML_DTDVALID | LIBXML_NOENT | LIBXML_DTDATTR.
		// Disabling network while connection before we load xml. This is not fool proof.
		// phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_set_error_handler -- We need this function to handle errors.
		$old_error_handler = set_error_handler( array( 'MOSAML\SRC\Utils\XML_Utility', 'handle_xml_error' ) );
		$is_xml_loaded     = $document->loadXML( $xml, LIBXML_NONET );
		restore_error_handler();
		// Iterate over the child nodes and invalidated XML if DOCTYPE node is found.
		if ( $is_xml_loaded ) {
			// phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- childNodes is predefined variable from DOMDocument class.
			foreach ( $document->childNodes as $child ) {
				// phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- nodeType is predefined variable from DOMDocument class.
				if ( XML_DOCUMENT_TYPE_NODE === $child->nodeType ) {
					throw new Invalid_XML_Exception( 'Invalid XML Detected.' );
				}
			}
			return $document;
		}
		throw new Invalid_XML_Exception( 'Invalid XML Detected.' );
	}

	/**
	 * Get the items of the DOMNodeList as an array.
	 *
	 * @param DOMNodeList $node_list The node list.
	 * @return array
	 */
	public static function get_list_items_as_array( DOMNodeList $node_list ) {
		$arr = array();
		if ( 0 < $node_list->length ) {
			foreach ( $node_list as $node ) {
				$arr[] = $node;
			}
		}
		return $arr;
	}

	/**
	 * Check if iconv is installed.
	 *
	 * @return bool
	 */
	public static function is_iconv_installed() {

		if ( in_array( 'iconv', get_loaded_extensions(), true ) ) {
			return true;
		}

		return false;
	}

	/**
	 * Throw exception if no or multiple nodes are found.
	 *
	 * @param string $name The name of the node.
	 * @param string $exception_type The type of exception to throw.
	 * @return void
	 * @throws Invalid_Assertion_Exception If the SAML response is invalid.
	 * @throws Invalid_XML_Exception If the XML is invalid.
	 */
	public static function throw_exception_if_no_or_multiple_nodes( string $name, string $exception_type ) {
		switch ( $exception_type ) {
			case 'no_attribute':
				throw new Invalid_Assertion_Exception( 'Missing required attribute : ' . esc_html( $name ) );
			case 'no_node':
				throw new Invalid_Assertion_Exception( 'Missing required node : ' . esc_html( $name ) );
			case 'multiple_nodes':
				throw new Invalid_Assertion_Exception( 'Multiple nodes found : ' . esc_html( $name ) );
			case 'both':
				throw new Invalid_Assertion_Exception( 'Missing or multiple nodes found : ' . esc_html( $name ) );
			default:
				throw new Invalid_XML_Exception( 'Invalid XML Detected.' );
		}
	}

	/**
	 * Validate and set attributes.
	 *
	 * @param SAML_Response_Handler|SAML_Request_Handler        $handler_obj The handler object.
	 * @param DOMElement                                        $context The context.
	 * @param SAML_Response_DTO|Assertions_DTO|SAML_Request_DTO $saml_dto The DTO object.
	 * @param string                                            $name The name of the node.
	 * @param array                                             $attribute_map The attribute map.
	 * @return void
	 * @throws Invalid_XML_Exception If the XML is invalid.
	 */
	public static function validate_and_set_attributes( $handler_obj, DOMElement $context, $saml_dto, string $name, array $attribute_map ) {
		foreach ( $attribute_map as $attr_key => $attr_value ) {
			if ( ( ! $context->hasAttribute( $attr_value ) || '' === $context->getAttribute( $attr_value ) ) && ( isset( XML_Constants::NO_OR_MULTIPLE_NODE_ATTRIBUTE_VALIDATION[ $attr_key ] ) && XML_Constants::NO_ATTRIBUTE === XML_Constants::NO_OR_MULTIPLE_NODE_ATTRIBUTE_VALIDATION[ $attr_key ] ) ) {
				self::throw_exception_if_no_or_multiple_nodes( $attr_value, XML_Constants::NO_ATTRIBUTE );
			}
			if ( $context->hasAttribute( $attr_value ) && '' !== $context->getAttribute( $attr_value ) ) {
				$method_name = 'set_' . $name . '_' . $attr_key;
				if ( method_exists( $saml_dto, $method_name ) ) {
					$saml_dto->$method_name( $context->getAttribute( $attr_value ) );
				}
			}

			if ( ! empty( XML_Constants::REQUIRED_VALIDATIONS_WHILE_PARSING[ $name ] ) ) {
				$handler_obj->{ XML_Constants::REQUIRED_VALIDATIONS_WHILE_PARSING[ $name ] }( $saml_dto );
			}
		}
	}

	/**
	 * Get the text content of the node.
	 *
	 * @param DOMNodeList $node The node.
	 * @return string|array
	 */
	public static function get_node_text_content( DOMNodeList $node ) {
		if ( 1 === $node->length ) {
			return $node->item( 0 )->textContent;
		}

		$res_arr = array();
		foreach ( $node as $item ) {
            // phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- localName is a valid property of DOMElement.
			$res_arr[] = $item->textContent;
		}
		return $res_arr;
	}

	/**
	 * Validate and set nodes.
	 *
	 * @param SAML_Response_Handler|SAML_Request_Handler        $handler_obj The handler object.
	 * @param DOMElement                                        $context The context.
	 * @param SAML_Response_DTO|Assertions_DTO|SAML_Request_DTO $saml_dto The DTO object.
	 * @param array                                             $node_map The node map.
	 * @return void
	 */
	public static function validate_and_set_nodes( $handler_obj, DOMElement $context, $saml_dto, array $node_map ) {
		foreach ( $node_map as $name => $query ) {
			if ( empty( $query ) && ! empty( XML_Constants::NODE_ATTRIBUTES_MAP[ $name ] ) ) {
				self::validate_and_set_attributes( $handler_obj, $context, $saml_dto, $name, XML_Constants::NODE_ATTRIBUTES_MAP[ $name ] );
				continue;
			}

			$current_node      = $handler_obj->xpath->query( $query, $context );
			$current_node_item = $current_node->item( 0 );

			$no_or_multiple_nodes_validation = ! empty( XML_Constants::NO_OR_MULTIPLE_NODE_ATTRIBUTE_VALIDATION[ $name ] ) ? XML_Constants::NO_OR_MULTIPLE_NODE_ATTRIBUTE_VALIDATION[ $name ] : '';

			if ( ! $current_node_item instanceof DOMElement ) {
				if ( XML_Constants::NO_NODE === $no_or_multiple_nodes_validation || XML_Constants::BOTH === $no_or_multiple_nodes_validation ) {
					self::throw_exception_if_no_or_multiple_nodes( $name, $no_or_multiple_nodes_validation );
				}
				continue;
			}

			if ( ( 1 < $current_node->length && XML_Constants::MULTIPLE_NODES === $no_or_multiple_nodes_validation ) || ( 1 !== $current_node->length && XML_Constants::BOTH === $no_or_multiple_nodes_validation ) ) {
				self::throw_exception_if_no_or_multiple_nodes( $name, $no_or_multiple_nodes_validation );
			}

			if ( ! empty( XML_Constants::NODE_ATTRIBUTES_MAP[ $name ] ) ) {
				self::validate_and_set_attributes( $handler_obj, $current_node_item, $saml_dto, $name, XML_Constants::NODE_ATTRIBUTES_MAP[ $name ] );
			}

			if ( ! empty( XML_Constants::SUBNODES_QUERY_MAP[ $name ] ) ) {
				self::validate_and_set_nodes( $handler_obj, $current_node_item, $saml_dto, XML_Constants::SUBNODES_QUERY_MAP[ $name ] );
			}

			$method_name  = 'set_' . $name;
			$value_to_set = '';
			if ( method_exists( $saml_dto, $method_name ) ) {
				$to_set       = ! empty( XML_Constants::NODE_TO_SET_VALUE_MAP[ $name ] ) ? XML_Constants::NODE_TO_SET_VALUE_MAP[ $name ] : 'text-content';
				$value_to_set = 'text-content' === $to_set ? self::get_node_text_content( $current_node ) : $current_node_item;
				$saml_dto->$method_name( $value_to_set );
			}

			if ( ! empty( XML_Constants::REQUIRED_VALIDATIONS_WHILE_PARSING[ $name ] ) ) {
				$handler_obj->{ XML_Constants::REQUIRED_VALIDATIONS_WHILE_PARSING[ $name ] }( $saml_dto );
			}
		}
	}



	/**
	 * Function to validate the encoding and compression of the XML passed
	 * and returns the decompressed XML.
	 *
	 * @param string $xml The compressed XML to be validated.
	 * @param string $request_param The request parameter to check if the XML is compressed.
	 * @return string The decompressed and validated XML.
	 *
	 * @throws Invalid_XML_Exception Thrown when the SAML Request received
	 * is not a valid format of the request.
	 */
	public static function validate_compressed_xml( $xml, $request_param ) {
		// phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_decode -- Decoding is required to convert the incoming SAML response to XML.
		$compressed_xml = base64_decode( $xml );

		if ( false === $compressed_xml ) {
			throw new Invalid_XML_Exception( 'Invalid XML Encoding.' );
		}

		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Nonce verification not required since we are dealing with get params here.
		if ( empty( $_GET[ $request_param ] ) ) {
			return $compressed_xml;
		}

		// phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_set_error_handler -- Needed to prevent gzinflate warnings.
		set_error_handler(
			static function ( $errno, $errstr ) {
				unset( $errno, $errstr );
				return true;
			}
		);
		$decompressed_xml = gzinflate( $compressed_xml );
		restore_error_handler();
		if ( false === $decompressed_xml ) {
			throw new Invalid_XML_Exception( 'Invalid XML Compression.' );
		}

		return $decompressed_xml;
	}

	/**
	 * Signs the XML and adds a signature node to it.
	 *
	 * @param string $xml The XML to sign.
	 * @param object $saml_request_dto The SAML request DTO.
	 * @param string $insert_before_tag_name The tag name to insert the signature before.
	 * @return string The signed XML.
	 */
	public static function sign_xml( $xml, $saml_request_dto, $insert_before_tag_name = '' ) {
		$param = array( 'type' => 'private' );
		$key   = new XMLSecurityKey( XMLSecurityKey::RSA_SHA256, $param );

		$private_key_path   = ( $saml_request_dto->get_sp_certificates() )->private_key;
		$public_certificate = ( $saml_request_dto->get_sp_certificates() )->public_key;
		$key->loadKey( $private_key_path, false );

		$document = Utility::safe_load_xml( $xml, Error_Codes_Enums::$error_codes['WPSAMLERR028'] );
		// PHPCS:Ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase
		$element = $document->firstChild;
		if ( ! empty( $insert_before_tag_name ) ) {
			$dom_node = $document->getElementsByTagName( $insert_before_tag_name )->item( 0 );
			self::insert_signature( $key, array( $public_certificate ), $element, $dom_node );
		} else {
			self::insert_signature( $key, array( $public_certificate ), $element );
		}
		//PHPCS:Ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- Saving the XML to a string.
		$request_xml = $element->ownerDocument->saveXML( $element );
		// PHPCS:Ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode -- Encoding the XML to base64.
		$base64_encoded_xml = base64_encode( $request_xml );
		return $base64_encoded_xml;
	}

	/**
	 * Insert a Signature-node.
	 *
	 * @param XMLSecurityKey $key           The key we should use to sign the message.
	 * @param array          $certificates  The certificates we should add to the signature node.
	 * @param DOMElement     $root          The XML node we should sign.
	 * @param DOMNode|null   $insert_before  The XML element we should insert the signature element before. It can be null.
	 */
	public static function insert_signature( XMLSecurityKey $key, array $certificates, DOMElement $root, $insert_before = null ) {

		$obj_xml_sec_dsig = new XMLSecurityDSig();
		$obj_xml_sec_dsig->setCanonicalMethod( XMLSecurityDSig::EXC_C14N );

		switch ( $key->type ) {
			case XMLSecurityKey::RSA_SHA256:
				$type = XMLSecurityDSig::SHA256;
				break;
			case XMLSecurityKey::RSA_SHA384:
				$type = XMLSecurityDSig::SHA384;
				break;
			case XMLSecurityKey::RSA_SHA512:
				$type = XMLSecurityDSig::SHA512;
				break;
			default:
				$type = XMLSecurityDSig::SHA1;
		}

		$obj_xml_sec_dsig->addReferenceList(
			array( $root ),
			$type,
			array( 'http://www.w3.org/2000/09/xmldsig#enveloped-signature', XMLSecurityDSig::EXC_C14N ),
			array(
				'id_name'   => 'ID',
				'overwrite' => false,
			)
		);

		$obj_xml_sec_dsig->sign( $key );

		foreach ( $certificates as $certificate ) {
			$obj_xml_sec_dsig->add509Cert( $certificate, true );
		}

		$obj_xml_sec_dsig->insertSignature( $root, $insert_before );
	}
}
