<?php
/**
 * SAML Request Handler.
 * This class handles the creation, relay state management, and sending of SAML authentication requests for SSO.
 * It provides base logic for SAML request handling, which can be extended by Standard, Premium, and Enterprise handlers.
 *
 * @package MOSAML\Module\Standard\Handler\SAML
 */

namespace MOSAML\Module\Standard\Handler\SAML;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\Module\Base\Handler\SAML\SAML_Request_Handler as Base_SAML_Request_Handler;
use MOSAML\SRC\DTO\SAML_Request_DTO;
use MOSAML\Traits\Instance;
use RobRichards\XMLSecLibs\XMLSecurityKey;
use MOSAML\SRC\Classes\Debug_Logger;
use RobRichards\XMLSecLibs\XMLSecurityDSig;
use MOSAML\Module\Base\Handler\Admin\Certificate_Data_Handler;
use DOMDocument;

/**
 * Standard SAML Request Handler.
 *
 * This class extends the Base_SAML_Request_Handler and provides additional
 * functionality for handling SAML requests.
 */
class SAML_Request_Handler extends Base_SAML_Request_Handler {

	use Instance;

	/**
	 * Handles the SAML request process, including relay state, request creation, and redirect URL setup.
	 *
	 * @param SAML_Request_DTO $saml_request_dto The SAML request DTO to populate and use.
	 * @return void
	 */
	public function handle_saml_request( SAML_Request_DTO $saml_request_dto ) {

		$this->get_relay_state( $saml_request_dto );
		$this->create_saml_request( $saml_request_dto );

		$this->send_saml_request( $saml_request_dto );
	}

	/**
	 * Builds the SAML login redirect URL and sets it in the SAML request DTO.
	 *
	 * @param SAML_Request_DTO $saml_request_dto The SAML request DTO to update.
	 * @return void
	 */
	public function send_saml_request( SAML_Request_DTO $saml_request_dto ) {
		parent::send_saml_request( $saml_request_dto );

		$saml_request = $saml_request_dto->get_saml_request();
		$relay_state  = $saml_request_dto->get_relay_state();
		$sso_url      = $saml_request_dto->get_idp_details()->sso_url;
		$binding      = $saml_request_dto->get_idp_details()->sso_binding;
		Debug_Logger::log( '[SAML Request] Protocol Binding: ' . $binding );
		if ( 'HttpRedirect' === $saml_request_dto->get_idp_details()->sso_binding ) {
			if ( 'checked' === $saml_request_dto->get_idp_details()->sign_sso_slo_request ) {
				$redirect = $sso_url;
				// PHPCS:Ignore WordPress.PHP.DiscouragedPHPFunctions.urlencode_urlencode -- Encoding the signature for URL.	
				$saml_request_param = 'SAMLRequest=' . $saml_request . '&RelayState=' . $relay_state . '&SigAlg=' . urlencode( XMLSecurityKey::RSA_SHA256 );
				$param              = array( 'type' => 'private' );
				$key                = new XMLSecurityKey( XMLSecurityKey::RSA_SHA256, $param );
				// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- SSO redirect parameter.
				if ( isset( $_REQUEST['option'] ) && 'testidpconfig' === $_REQUEST['option'] && isset( $_REQUEST['newcert'] ) ) {
					$cert_file_path = file_get_contents( plugin_dir_path( __FILE__ ) . 'resources' . DIRECTORY_SEPARATOR . \MOSAML\SRC\Constant\Constants::SP_PRIVATE_KEY_FILE_NAME );
				} else {
					$cert_file_path = ( $saml_request_dto->get_sp_certificates() )->private_key;
				}
				if ( empty( $cert_file_path ) ) {
					$redirect .= '?SAMLRequest=' . $saml_request . '&RelayState=' . $relay_state;
				} else {
					$key->loadKey( $cert_file_path, false );
					$signature = $key->signData( $saml_request_param );
					// PHPCS:IGNORE WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode -- Encoding the signature to sign Data.
					$signature = base64_encode( $signature );
					// PHPCS:Ignore WordPress.PHP.DiscouragedPHPFunctions.urlencode_urlencode -- Encoding the signature for URL.
					$redirect .= '?' . $saml_request_param . '&Signature=' . urlencode( $signature );
					Debug_Logger::log( '[SAML Request] Signed Request: YES' );
				}
				$saml_request_dto->set_redirect( $redirect );
			}
		} elseif ( 'HttpPost' === $saml_request_dto->get_idp_details()->sso_binding ) {
			if ( 'checked' === $saml_request_dto->get_idp_details()->sign_sso_slo_request ) {
				// PHPCS:IGNORE WordPress.Security.NonceVerification.Recommended -- SSO post parameter.
				if ( isset( $_REQUEST['option'] ) && 'testidpconfig' === $_REQUEST['option'] && isset( $_REQUEST['newcert'] ) ) {
					$base64_encoded_xml = $this->sign_xml( $saml_request, $saml_request_dto, 'NameIDPolicy', true );
				} else {
					$base64_encoded_xml = $this->sign_xml( $saml_request, $saml_request_dto, 'NameIDPolicy' );
				}
				Debug_Logger::log( '[SAML Request] Signed Request: YES' );
				$this->post_saml_request( $sso_url, $base64_encoded_xml, $relay_state );
			} else {
				//phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode -- SSO post parameter.
				$base64_encoded_xml = base64_encode( $saml_request );
				$this->post_saml_request( $sso_url, $base64_encoded_xml, $relay_state );
			}
		}
	}

	/**
	 * Creates a SAML authentication request and sets it in the provided DTO.
	 *
	 * @param SAML_Request_DTO $saml_request_dto The SAML request DTO to update.
	 * @return void
	 */
	public function create_saml_request( SAML_Request_DTO $saml_request_dto ) {
		$saml_request_dto->set_name_id_format( $saml_request_dto->get_idp_details()->name_id_format );
		$certificate_data_handler = new Certificate_Data_Handler();

		if ( $saml_request_dto->get_idp_details()->sp_certificate && $saml_request_dto->get_idp_details()->sp_private_key ) {
			$certificate_data_handler->public_key  = $saml_request_dto->get_idp_details()->sp_certificate;
			$certificate_data_handler->private_key = $saml_request_dto->get_idp_details()->sp_private_key;
			$saml_request_dto->set_sp_certificates( $certificate_data_handler );
		} else {
			$saml_request_dto->set_sp_certificates( $certificate_data_handler->get_data() );
		}

		parent::create_saml_request( $saml_request_dto );
	}

	/**
	 * Sign the XML.
	 *
	 * @param string           $xml The XML to sign (raw XML for HTTP-POST, URL encoded for HTTP-Redirect).
	 * @param SAML_Request_DTO $saml_request_dto The SAML request DTO.
	 * @param string           $insert_before_tag_name The tag name to insert the signature before.
	 * @param bool             $new_cert Whether to use the new certificate.
	 * @return string The signed XML.
	 */
	private function sign_xml( $xml, $saml_request_dto, $insert_before_tag_name = '', $new_cert = false ) {
		$param = array( 'type' => 'private' );
		$key   = new XMLSecurityKey( XMLSecurityKey::RSA_SHA256, $param );
		if ( $new_cert ) {
			$private_key_path   = file_get_contents( plugin_dir_path( __FILE__ ) . 'resources' . DIRECTORY_SEPARATOR . \MOSAML\SRC\Constant\Constants::SP_PRIVATE_KEY_FILE_NAME );
			$public_certificate = file_get_contents( plugin_dir_path( __FILE__ ) . 'resources' . DIRECTORY_SEPARATOR . \MOSAML\SRC\Constant\Constants::SP_CERT_FILE_NAME );
		} else {
			$private_key_path   = ( $saml_request_dto->get_sp_certificates() )->private_key;
			$public_certificate = ( $saml_request_dto->get_sp_certificates() )->public_key;
		}
		$key->loadKey( $private_key_path, false );
		$xml_to_sign = $xml;
		if ( 'HttpRedirect' === $saml_request_dto->get_idp_details()->sso_binding ) {
			$url_decoded_xml = urldecode( $xml );
			//phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_decode -- Decoding SAML request for signing.
			$deflated_xml = base64_decode( $url_decoded_xml );
			$xml_to_sign  = gzinflate( $deflated_xml );
		}

		$document = new DOMDocument();
		$document->loadXML( $xml_to_sign );
		// PHPCS:Ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase
		$element = $document->firstChild;
		if ( ! empty( $insert_before_tag_name ) ) {
			$dom_node = $document->getElementsByTagName( $insert_before_tag_name )->item( 0 );
			$this->insert_signature( $key, array( $public_certificate ), $element, $dom_node );
		} else {
			$this->insert_signature( $key, array( $public_certificate ), $element );
		}
		//PHPCS:Ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- Saving the XML to a string.
		$request_xml = $element->ownerDocument->saveXML( $element );

		if ( 'HttpPost' === $saml_request_dto->get_idp_details()->sso_binding ) {
			//phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode -- Encoding the signed XML to base64.
			return base64_encode( $request_xml );
		}

		$deflated_str = gzdeflate( $request_xml );
		//phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode -- Encoding the signed XML to base64.
		$base64_encoded_str = base64_encode( $deflated_str );
		//phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.urlencode_urlencode -- URL encoding for redirect.
		$url_encoded = urlencode( $base64_encoded_str );
		return $url_encoded;
	}

	/**
	 * Insert a Signature-node.
	 *
	 * @param XMLSecurityKey $key           The key we should use to sign the message.
	 * @param array          $certificates  The certificates we should add to the signature node.
	 * @param \DOMElement    $root          The XML node we should sign.
	 * @param DOMNode|null   $insert_before  The XML element we should insert the signature element before. It can be null.
	 */
	private function insert_signature( XMLSecurityKey $key, array $certificates, \DOMElement $root, $insert_before = null ) {
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

	/**
	 * Post the SAML request.
	 *
	 * @param string $url The URL to post the SAML request to.
	 * @param string $saml_request The SAML request XML.
	 * @param string $relay_state The relay state.
	 * @return void
	 */
	public function post_saml_request( $url, $saml_request, $relay_state ) {
		echo '
		<html>
			<body>Please wait...
				<form action="' . esc_url( $url ) . '" method="post" id="saml-request-form">
					<input type="hidden" name="SAMLRequest" value="' . esc_attr( $saml_request ) . '" />
					<input type="hidden" name="RelayState" value="' . esc_attr( $relay_state ) . '" />
				</form>
				<script>document.getElementById(\'saml-request-form\').submit();</script>
			</body>
		</html>';
		exit();
	}
}
