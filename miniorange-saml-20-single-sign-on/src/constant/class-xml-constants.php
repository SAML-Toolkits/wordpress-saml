<?php
/**
 * XML Constants
 *
 * @package MOSAML\SRC\Constant
 */

namespace MOSAML\SRC\Constant;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * XML Constants
 *
 * @package MOSAML\SRC\Constant
 */
class XML_Constants {

	/**
	 * To set value text content
	 *
	 * @var string
	 */
	const TO_SET_VALUE_TEXT_CONTENT = 'text-content';

	/**
	 * To set value node
	 *
	 * @var string
	 */
	const TO_SET_VALUE_NODE = 'node';

	/**
	 * To set value attribute
	 *
	 * @var string
	 */
	const NO_ATTRIBUTE = 'no_attribute';

	/**
	 * No node
	 *
	 * @var string
	 */
	const NO_NODE = 'no_node';

	/**
	 * Multiple nodes
	 *
	 * @var string
	 */
	const MULTIPLE_NODES = 'multiple_nodes';

	/**
	 * Both
	 *
	 * @var string
	 */
	const BOTH = 'both';

	/**
	 * Encoding CP1252
	 *
	 * @var string
	 */
	const ENCODING_CP1252 = 'CP1252';

	/**
	 * Encoding UTF-8
	 *
	 * @var string
	 */
	const ENCODING_UTF_8 = 'UTF-8';

	/**
	 * Response namespaces
	 *
	 * @var array
	 */
	const RESPONSE_NAMESPACES = array(
		'samlp' => 'urn:oasis:names:tc:SAML:2.0:protocol',
		'saml'  => 'urn:oasis:names:tc:SAML:2.0:assertion',
		'ds'    => 'http://www.w3.org/2000/09/xmldsig#',
		'xenc'  => 'http://www.w3.org/2001/04/xmlenc#',
	);

	/**
	 * Login response nodes query map
	 *
	 * @var array
	 */
	const NODES_QUERY_MAP = array(
		'response'  => array(
			'response'       => '',
			'status'         => './samlp:Status',
			'issuer'         => './saml:Issuer',
			'signature_node' => './ds:Signature',
		),
		'assertion' => array(
			'assertion'           => '',
			'issuer'              => './saml:Issuer',
			'signature_node'      => './ds:Signature',
			'subject'             => './saml:Subject',
			'conditions'          => './saml:Conditions',
			'authn_statement'     => './saml:AuthnStatement',
			'attribute_statement' => './saml:AttributeStatement',
		),
		'request'   => array(
			'request' => '',
			'name_id' => './saml:NameID | ./saml:EncryptedID/xenc:EncryptedData',
			'issuer'  => './saml:Issuer',
		),
	);

	/**
	 * Login response subnodes query map
	 *
	 * @var array
	 */
	const SUBNODES_QUERY_MAP = array(
		'status'              => array(
			'status_code'    => './samlp:StatusCode',
			'status_message' => './samlp:StatusMessage',
		),
		'subject'             => array(
			'name_id' => './saml:NameID | ./saml:EncryptedID/xenc:EncryptedData',
		),
		'conditions'          => array(
			'audiences' => './saml:AudienceRestriction/saml:Audience',
		),
		'authn_statement'     => array(
			'authn_context_decl_ref'  => './saml:AuthnContext/saml:AuthnContextDeclRef',
			'authn_context_decl'      => './saml:AuthnContext/saml:AuthnContextDecl',
			'authn_context_class_ref' => './saml:AuthnContext/saml:AuthnContextClassRef',
		),
		'attribute_statement' => array(
			'attribute'           => './saml:Attribute',
			'encrypted_attribute' => './saml:EncryptedAttribute',
		),
		'encrypted_attribute' => array(
			'encrypted_data' => './saml:EncryptedData',
		),
		'signature_node'      => array(
			'signature_method' => './ds:SignedInfo/ds:SignatureMethod',
			'certificates'     => './ds:KeyInfo/ds:X509Data/ds:X509Certificate',
		),
	);

	/**
	 * Node attributes map
	 *
	 * @var array
	 */
	const NODE_ATTRIBUTES_MAP = array(
		'response'         => array(
			'destination' => 'Destination',
		),
		'assertion'        => array(
			'id'            => 'ID',
			'version'       => 'Version',
			'issue_instant' => 'IssueInstant',
		),
		'request'          => array(
			'id'          => 'ID',
			'destination' => 'Destination',
			'version'     => 'Version',
		),
		'status_code'      => array(
			'value' => 'Value',
		),
		'signature_method' => array(
			'algorithm' => 'Algorithm',
		),
		'name_id'          => array(
			'format' => 'Format',
		),
		'conditions'       => array(
			'not_before'      => 'NotBefore',
			'not_on_or_after' => 'NotOnOrAfter',
		),
		'authn_statement'  => array(
			'authn_instant'           => 'AuthnInstant',
			'session_index'           => 'SessionIndex',
			'session_not_on_or_after' => 'SessionNotOnOrAfter',
		),
	);

	/**
	 * Node to set map
	 *
	 * @var array
	 */
	const NODE_TO_SET_VALUE_MAP = array(
		'signature_node' => self::TO_SET_VALUE_NODE,
	);

	/**
	 * Node validation functions map
	 *
	 * @var array
	 */
	const REQUIRED_VALIDATIONS_WHILE_PARSING = array(
		'status'         => 'validate_status',
		'version'        => 'validate_version',
		'signature_node' => 'validate_signature_element',

	);

	/**
	 * No or multiple nodes validation
	 *
	 * @var array
	 */
	const NO_OR_MULTIPLE_NODE_ATTRIBUTE_VALIDATION = array(
		'destination'      => self::NO_ATTRIBUTE,
		'id'               => self::NO_ATTRIBUTE,
		'version'          => self::NO_ATTRIBUTE,
		'authn_instant'    => self::NO_ATTRIBUTE,
		'algorithm'        => self::NO_ATTRIBUTE,
		'status'           => self::BOTH,
		'signature_node'   => self::MULTIPLE_NODES,
		'signature_method' => self::BOTH,
		'name_id'          => self::BOTH,
	);
}
