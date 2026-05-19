<?php
/**
 * SAML Response Handler file for Standard Version.
 *
 * @package MOSAML\Module\Standard\Handler\SAML
 */

namespace MOSAML\Module\Standard\Handler\SAML;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\Module\Base\Handler\SAML\SAML_Response_Handler as Base_SAML_Response_Handler;
use MOSAML\SRC\Exception\Invalid_Assertion_Exception;
use MOSAML\SRC\Utils\XML_Utility;
use MOSAML\SRC\DTO\Assertions_DTO;
use MOSAML\SRC\Constant\XML_Constants;
use RobRichards\XMLSecLibs\XMLSecurityKey;
use RobRichards\XMLSecLibs\XMLSecEnc;
use DOMElement;
use DOMDocument;
use DOMXPath;
use DOMNodeList;
use Exception;
use MOSAML\Module\Base\Handler\Admin\Certificate_Data_Handler;
use MOSAML\SRC\Exception\Element_Decryption_Exception;

/**
 * SAML Response Handler class for Standard Version.
 *
 * This class handles the basic parsing of SAML responses. It focuses on
 * extracting the response envelope and delegating assertion parsing to
 * the SAML_Assertion_Parser class.
 *
 * @package MOSAML\Module\Standard\Handler
 */
class SAML_Response_Handler extends Base_SAML_Response_Handler {

	/**
	 * Get the assertion nodes from the response. Throws exception if no assertion node found.
	 *
	 * @param DOMElement $response_node The response node.
	 * @return DOMNodeList
	 * @throws Invalid_Assertion_Exception If no assertion is found.
	 */
	public function get_assertion_nodes_from_response( DOMElement $response_node ) {
		$assertion_nodes           = $this->xpath->query( './saml:Assertion', $response_node );
		$encrypted_assertion_nodes = $this->xpath->query( './saml:EncryptedAssertion', $response_node );

		$final_assertion_nodes = XML_Utility::get_list_items_as_array( $assertion_nodes );

		if ( $encrypted_assertion_nodes && 0 < $encrypted_assertion_nodes->length ) {
			foreach ( $encrypted_assertion_nodes as $encrypted_assertion_node ) {
				$encrypted_data = $this->xpath->query( './xenc:EncryptedData', $encrypted_assertion_node );
				if ( 1 !== $encrypted_data->length ) {
					throw new Invalid_Assertion_Exception( 'Missing or multiple nodes found : EncryptedData.' );
				}
				$encrypted_data_node = $encrypted_data->item( 0 );
				$algorithm_nodes     = $this->xpath->query( '//*[local-name()="EncryptedKey"]/*[local-name()="EncryptionMethod"]/@Algorithm' );
				if ( 1 !== $algorithm_nodes->length ) {
					throw new Invalid_Assertion_Exception( 'Missing or multiple nodes found : EncryptionMethod.' );
				}

				$decrypted_assertion_node = $this->decrypt_and_return_node( $encrypted_data_node, $algorithm_nodes );
				if ( $decrypted_assertion_node instanceof DOMDocument ) {
					$doc = $decrypted_assertion_node;
				} else {
					$doc = $decrypted_assertion_node->ownerDocument; // phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- ownerDocument is a valid property of DOMElement.
				}

				if ( is_null( $this->xpath ) || ! $this->xpath->document->isSameNode( $doc ) ) {
					$this->xpath = new DOMXPath( $doc );

					foreach ( XML_Constants::RESPONSE_NAMESPACES as $prefix => $uri ) {
						$this->xpath->registerNamespace( $prefix, $uri );
					}
				}
				$final_assertion_nodes[] = $decrypted_assertion_node;
			}
		}

		if ( empty( $final_assertion_nodes ) ) {
			throw new Invalid_Assertion_Exception( 'No assertions found in SAML response.' );
		}
		return $final_assertion_nodes;
	}

	/**
	 * Parse and set user attributes received from the SAML response.
	 *
	 * @param Assertions_DTO $assertions_dto The assertions DTO.
	 * @param DOMElement     $assertion_node The assertion node.
	 * @return void
	 */
	public function parse_and_set_attributes( Assertions_DTO $assertions_dto, DOMElement $assertion_node ) {
		parent::parse_and_set_attributes( $assertions_dto, $assertion_node );

		$attributes_arr            = ! empty( $assertions_dto->get_attributes() ) ? $assertions_dto->get_attributes() : array();
		$encrypted_attribute_nodes = $this->xpath->query( './saml:AttributeStatement/saml:EncryptedAttribute', $assertion_node );

		foreach ( $encrypted_attribute_nodes as $encrypted_attribute_node ) {
			$encrypted_data = $this->xpath->query( './xenc:EncryptedData', $encrypted_attribute_node );
			if ( 1 !== $encrypted_data->length ) {
				continue;
			}
			$encrypted_data_node = $encrypted_data->item( 0 );
			$algorithm_nodes     = $this->xpath->query( '//*[local-name()="EncryptedKey"]/*[local-name()="EncryptionMethod"]/@Algorithm', $encrypted_data_node );
			if ( 1 !== $algorithm_nodes->length ) {
				continue;
			}
			$decrypted_attribute_node = $this->decrypt_and_return_node( $encrypted_data_node, $algorithm_nodes );
			$attribute_name           = $decrypted_attribute_node->getAttribute( 'Name' );
			if ( ! empty( $attribute_name ) ) {
				$value_nodes                       = $this->xpath->query( './saml:AttributeValue', $decrypted_attribute_node );
				$attributes_arr[ $attribute_name ] = XML_Utility::get_node_text_content( $value_nodes );
			}
		}
		$assertions_dto->set_attributes( $attributes_arr );
	}

	/**
	 * Decrypt and return the encrypted node.
	 *
	 * @param DOMElement  $encrypted_node The encrypted node.
	 * @param DOMNodeList $algorithm_nodes The algorithm nodes.
	 * @return DOMElement
	 */
	public function decrypt_and_return_node( DOMElement $encrypted_node, DOMNodeList $algorithm_nodes ) {

		$method = $algorithm_nodes->item( 0 )->nodeValue;
		$method = $this->validate_encryption_method( $method );

		$key = new XMLSecurityKey( $method, array( 'type' => 'private' ) );
		$key->loadKey( ( ( new Certificate_Data_Handler() )->get_data() )->private_key, false );

		return $this->decrypt_element( $encrypted_node, $key );
	}

	/**
	 * Validates if the encryption method is supported in the RobRichards library.
	 *
	 * @param string $method The method.
	 * @return string
	 * @throws Element_Decryption_Exception If the encryption method is invalid.
	 */
	public function validate_encryption_method( string $method ) {
		switch ( $method ) {
			case 'http://www.w3.org/2001/04/xmlenc#tripledes-cbc':
				return XMLSecurityKey::TRIPLEDES_CBC;

			case 'http://www.w3.org/2001/04/xmlenc#aes128-cbc':
				return XMLSecurityKey::AES128_CBC;

			case 'http://www.w3.org/2001/04/xmlenc#aes192-cbc':
				return XMLSecurityKey::AES192_CBC;

			case 'http://www.w3.org/2001/04/xmlenc#aes256-cbc':
				return XMLSecurityKey::AES256_CBC;

			case 'http://www.w3.org/2001/04/xmlenc#rsa-1_5':
				return XMLSecurityKey::RSA_1_5;

			case 'http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p':
				return XMLSecurityKey::RSA_OAEP_MGF1P;

			case 'http://www.w3.org/2000/09/xmldsig#dsa-sha1':
				return XMLSecurityKey::DSA_SHA1;

			case 'http://www.w3.org/2000/09/xmldsig#rsa-sha1':
				return XMLSecurityKey::RSA_SHA1;

			case 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256':
				return XMLSecurityKey::RSA_SHA256;

			case 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha384':
				return XMLSecurityKey::RSA_SHA384;

			case 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha512':
				return XMLSecurityKey::RSA_SHA512;

			default:
				throw new Element_Decryption_Exception( 'Invalid Encryption Method: ' . esc_html( $method ) );
		}
	}

	/**
	 * Decrypt an encrypted element.
	 *
	 * This is an internal helper function.
	 *
	 * @param  DOMElement     $encrypted_data_node The encrypted data.
	 * @param  XMLSecurityKey $input_key      The decryption key.
	 * @return DOMElement     The decrypted element.
	 * @throws Element_Decryption_Exception If the decryption fails.
	 */
	public function decrypt_element( DOMElement $encrypted_data_node, XMLSecurityKey $input_key ) {
		$enc = new XMLSecEnc();
		$enc->setNode( $encrypted_data_node );

		$enc->type     = $encrypted_data_node->getAttribute( 'Type' );
		$symmetric_key = $enc->locateKey( $encrypted_data_node );
		if ( ! $symmetric_key ) {
			throw new Element_Decryption_Exception( 'Could not locate key algorithm in encrypted data.' );
		}

		$symmetric_key_info = $enc->locateKeyInfo( $symmetric_key );
		if ( ! $symmetric_key_info ) {
			throw new Element_Decryption_Exception( 'Could not locate <dsig:KeyInfo> for the encrypted key.' );
		}
		$input_key_algo = $input_key->getAlgorithm();
        // phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- isEncrypted is a valid property of XMLSecEnc.
		if ( $symmetric_key_info->isEncrypted ) {
			$sym_key_info_algo = $symmetric_key_info->getAlgorithm();

			if ( XMLSecurityKey::RSA_OAEP_MGF1P === $sym_key_info_algo && XMLSecurityKey::RSA_1_5 === $input_key_algo ) {
				/*
				 * The RSA key formats are equal, so loading an RSA_1_5 key
				 * into an RSA_OAEP_MGF1P key can be done without problems.
				 * We therefore pretend that the input key is an
				 * RSA_OAEP_MGF1P key.
				 */
				$input_key_algo = XMLSecurityKey::RSA_OAEP_MGF1P;
			}
			/* Make sure that the input key format is the same as the one used to encrypt the key. */
			if ( $input_key_algo !== $sym_key_info_algo ) {
				throw new Element_Decryption_Exception(
					'Algorithm mismatch between input key and key used to encrypt ' .
					' the symmetric key for the message. Key was: ' .
					esc_html( $input_key_algo ) . '; message was: ' .
					esc_html( $sym_key_info_algo )
				);
			}
            // phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- encryptedCtx is a valid property of XMLSecEnc.
			$enc_key                 = $symmetric_key_info->encryptedCtx;
			$symmetric_key_info->key = $input_key->key;
			$key_size                = $symmetric_key->getSymmetricKeySize();
			if ( null === $key_size ) {
				/*
				To protect against "key oracle" attacks, we need to be able to create a
				 * symmetric key, and for that we need to know the key size.
				 */
				throw new Element_Decryption_Exception( 'Unknown key size for encryption algorithm: ' . esc_html( $symmetric_key->type ) );
			}
			try {
				$key = $enc_key->decryptKey( $symmetric_key_info );
				if ( strlen( $key ) !== $key_size ) {
					throw new Element_Decryption_Exception(
						'Unexpected key size (' . esc_html( strlen( $key ) * 8 ) . 'bits) for encryption algorithm: ' .
						esc_html( $symmetric_key->type )
					);
				}
			} catch ( Exception $e ) {
				/* We failed to decrypt this key. Log it, and substitute a "random" key. */

				/*
				* Create a replacement key, so that it looks like we fail in the same way as if the key was correctly padded.
				* We base the symmetric key on the encrypted key and private key, so that we always behave the
				* same way for a given input key.
				*/
				$encrypted_key = $enc_key->getCipherValue();
				$pkey          = openssl_pkey_get_details( $symmetric_key_info->key );
				$pkey          = sha1( (string) wp_json_encode( $pkey ), true );
				$key           = sha1( $encrypted_key . $pkey, true );
				/* Make sure that the key has the correct length. */
				if ( strlen( $key ) > $key_size ) {
					$key = substr( $key, 0, $key_size );
				} elseif ( strlen( $key ) < $key_size ) {
					$key = str_pad( $key, $key_size );
				}
			}
			$symmetric_key->loadkey( $key );
		} else {
			$sym_key_algo = $symmetric_key->getAlgorithm();
			/* Make sure that the input key has the correct format. */
			if ( $input_key_algo !== $sym_key_algo ) {
				throw new Element_Decryption_Exception(
					'Algorithm mismatch between input key and key in message. ' .
					'Key was: ' . esc_html( $input_key_algo ) . '; message was: ' .
					esc_html( $sym_key_algo )
				);
			}
			$symmetric_key = $input_key;
		}
		$algorithm = $symmetric_key->getAlgorithm();

		$decrypted = $enc->decryptNode( $symmetric_key, false );

		/*
		 * This is a workaround for the case where only a subset of the XML
		 * tree was serialized for encryption. In that case, we may miss the
		 * namespaces needed to parse the XML.
		 */
		$xml     = '<root xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ' .
					'xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">' .
			$decrypted .
			'</root>';
		$new_doc = XML_Utility::safe_load_xml( $xml );
		if ( ! $new_doc ) {
			throw new Element_Decryption_Exception( 'Failed to parse decrypted XML. Maybe the wrong sharedkey was used?' );
		}

        // phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- firstChild is a valid property of DOMElement.
		$decrypted_element = $new_doc->firstChild->firstChild;

		if ( null === $decrypted_element ) {
			throw new Element_Decryption_Exception( 'Missing encrypted element.' );
		}

		if ( ! ( $decrypted_element instanceof DOMElement ) ) {
			throw new Element_Decryption_Exception( 'Decrypted element was not actually a DOMElement.' );
		}

		return $decrypted_element;
	}
}
