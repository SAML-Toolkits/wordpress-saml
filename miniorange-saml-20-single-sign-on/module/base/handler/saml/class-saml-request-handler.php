<?php
/**
 * SAML Request Handler.
 * This class handles the creation, relay state management, and sending of SAML authentication requests for SSO.
 * It provides base logic for SAML request handling, which can be extended by Standard, Premium, and Enterprise handlers.
 *
 * @package MOSAML\Module\Base\Handler\SAML
 */

namespace MOSAML\Module\Base\Handler\SAML;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\Traits\Instance;
use MOSAML\SRC\Utils\Utility;
use MOSAML\SRC\Constant\Plugin_Options;
use MOSAML\Module\Base\Handler\Admin\SP_Endpoints_Data_Handler;
use MOSAML\SRC\DTO\SAML_Request_DTO;
use MOSAML\SRC\Constant\Constants;
use MOSAML\SRC\Classes\Debug_Logger;
use MOSAML\SRC\Utils\DB_Utils;

/**
 * This class handles the SAML request.
 */
class SAML_Request_Handler {

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
	 * Populates the relay state in the SAML request DTO based on the current request context.
	 *
	 * @param SAML_Request_DTO $saml_request_dto The SAML request DTO to update.
	 * @return void
	 */
	public function get_relay_state( SAML_Request_DTO $saml_request_dto ) {

		//phpcs:ignore WordPress.Security.NonceVerification.Recommended -- SSO redirect parameter.
		$request = isset( $_REQUEST ) ? $_REQUEST : array();

		if ( isset( $request['option'] ) && Plugin_Options::SAML_REQUEST_OPTION['TEST_CONFIG'] === $request['option'] ) {
			$send_relay_state = Plugin_Options::SAML_REQUEST_OPTION['TEST_CONFIG'];
		} elseif ( isset( $request['option'] ) && Plugin_Options::SAML_REQUEST_OPTION['END_USER_TEST_CONFIG'] === $request['option'] ) {
			$send_relay_state = Plugin_Options::SAML_REQUEST_OPTION['END_USER_TEST_CONFIG'];
		} elseif ( isset( $request['redirect_to'] ) ) {
			$send_relay_state = Utility::mo_saml_is_array( $request['redirect_to'] );
		} elseif ( ( $referer = wp_get_referer() ) && ( $validated = wp_validate_redirect( $referer, false ) ) && strpos( $validated, site_url() ) === 0 ) {
			$send_relay_state = $validated;
		} else {
			$send_relay_state = Utility::get_current_page_url();
		}

		$send_relay_state = $this->parse_relay_state( $send_relay_state );
		$send_relay_state = empty( $send_relay_state ) ? '/' : $send_relay_state;

		/**
		 * Filter to change the relay state sent in SAML Login Request
		 *
		 * @since 25.2.7
		 *
		 * @param string  $sendRelayState
		 */
		$send_relay_state = apply_filters( 'mosaml_pre_login_sso_relay_state_internal', $send_relay_state );
		$send_relay_state = rawurlencode( $send_relay_state );

		$saml_request_dto->set_relay_state( $send_relay_state );
	}

	/**
	 * Parses the relay state parameter from the request and returns the appropriate path.
	 *
	 * @param string $relay_state The relay state from the IDP or request.
	 * @return string
	 */
	private function parse_relay_state( $relay_state ) {

		if ( Plugin_Options::SAML_REQUEST_OPTION['TEST_CONFIG'] === $relay_state || Plugin_Options::SAML_REQUEST_OPTION['END_USER_TEST_CONFIG'] === $relay_state ) {
			return $relay_state;
		}

		$relay_path = wp_parse_url( $relay_state, PHP_URL_PATH );
		if ( wp_parse_url( $relay_state, PHP_URL_QUERY ) ) {
			$relay_query_paramter = wp_parse_url( $relay_state, PHP_URL_QUERY );
			$relay_path           = $relay_path . '?' . $relay_query_paramter;
		}
		if ( wp_parse_url( $relay_state, PHP_URL_FRAGMENT ) ) {
			$relay_fragment_identifier = wp_parse_url( $relay_state, PHP_URL_FRAGMENT );
			$relay_path                = $relay_path . '#' . $relay_fragment_identifier;
		}

		return $relay_path;
	}

	/**
	 * Creates a SAML authentication request and sets it in the provided DTO.
	 *
	 * @param SAML_Request_DTO $saml_request_dto The SAML request DTO to update.
	 * @return void
	 */
	public function create_saml_request( SAML_Request_DTO $saml_request_dto ) {
		$sp_details  = ( new SP_Endpoints_Data_Handler() )->get_data();
		$idp_details = $saml_request_dto->get_idp_details();
		$saml_request_dto->set_sp_details( $sp_details );

		if ( ! empty( $idp_details ) && ! empty( $idp_details->sp_entity_id ) ) {
			$sp_entity_id = $idp_details->sp_entity_id;
		} elseif ( ! empty( $sp_details ) && ! empty( $sp_details->sp_entity_id ) ) {
			$sp_entity_id = $sp_details->sp_entity_id;
		} else {
			$sp_entity_id = site_url() . '/wp-content/plugins/miniorange-saml-20-single-sign-on/';
		}

		if ( ! empty( $sp_details ) && ! empty( $sp_details->sp_base_url ) ) {
			$acs_url = rtrim( $sp_details->sp_base_url, '/' ) . '/';
		} else {
			$acs_url = site_url() . '/';
		}

		$force_auth_handler           = Utility::get_handler_object( 'force_authentication_data', true, 'admin' );
		$force_auth_data              = $force_auth_handler->get_data( array( 'subsite_id' => Utility::get_subsite_id_for_environment( DB_Utils::get_environment_details( 'id', true ) ) ) );
		$force_authentication_enabled = $force_auth_data->enable_force_authentication ? 'true' : 'false';
		$saml_request                 = $this->create_authn_request( $saml_request_dto, $acs_url, $sp_entity_id, $force_authentication_enabled );
		$saml_request_dto->set_saml_request( $saml_request );

		$relay_state = $saml_request_dto->get_relay_state();
		if ( Plugin_Options::SAML_REQUEST_OPTION['TEST_CONFIG'] === $relay_state || Plugin_Options::SAML_REQUEST_OPTION['END_USER_TEST_CONFIG'] === $relay_state ) {
			$idp_details           = $saml_request_dto->get_idp_details();
			$saml_request_to_store = $saml_request_dto->get_saml_request();
			if ( ! empty( $idp_details->id ) && ! empty( $saml_request_to_store ) ) {
				DB_Utils::insert_or_update(
					Constants::DATABASE_TABLE_NAMES['idp_details'],
					array( 'saml_request' => $saml_request_to_store ),
					array(
						'id'             => $idp_details->id,
						'environment_id' => DB_Utils::get_environment_details( 'id', false ),
					)
				);
			}
		}
	}

	/**
	 * Builds the SAML login redirect URL and sets it in the SAML request DTO.
	 *
	 * @param SAML_Request_DTO $saml_request_dto The SAML request DTO to update.
	 * @return void
	 */
	public function send_saml_request( SAML_Request_DTO $saml_request_dto ) {

		$redirect = apply_filters( 'mosaml_sso_url_internal', $saml_request_dto->get_idp_details()->sso_url, $saml_request_dto->get_idp_details()->idp_id );

		if ( strpos( $redirect, '?' ) !== false ) {
			$redirect .= '&';
		} else {
			$redirect .= '?';
		}
		$redirect .= 'SAMLRequest=' . $saml_request_dto->get_saml_request() . '&RelayState=' . $saml_request_dto->get_relay_state();

		$saml_request_dto->set_redirect( $redirect );
	}

	/**
	 * Creates a SAML authentication request.
	 *
	 * @param SAML_Request_DTO $saml_request_dto The SAML request DTO.
	 * @param string           $acs_url The ACS URL.
	 * @param string           $issuer The issuer of the SAML request.
	 * @param string           $force_authn Whether to force authentication.
	 * @return string
	 */
	public function create_authn_request( $saml_request_dto, $acs_url, $issuer, $force_authn = 'false' ) {

		$saml_nameid_format = $saml_request_dto->get_name_id_format();
		$saml_request_id    = Utility::generate_id();
		if ( 'unspecified' === $saml_nameid_format || empty( $saml_nameid_format ) ) {
			$saml_nameid_format = 'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified';
		}
		$destination     = is_object( $saml_request_dto->get_idp_details() ) && isset( $saml_request_dto->get_idp_details()->sso_url ) ? $saml_request_dto->get_idp_details()->sso_url : '';
		$request_xml_str = '<?xml version="1.0" encoding="UTF-8"?>' .
						'<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns="urn:oasis:names:tc:SAML:2.0:assertion" ID="' . $saml_request_id .
						'" Version="2.0" IssueInstant="' . Utility::generate_time_stamp() . '"';
		if ( 'true' === $force_authn ) {
			$request_xml_str .= ' ForceAuthn="true"';
		}
		$request_xml_str .= ' ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" AssertionConsumerServiceURL="' . $acs_url .
						'" Destination="' . $destination . '"><saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">' . $issuer .
			'</saml:Issuer><samlp:NameIDPolicy AllowCreate="true" Format="' . $saml_nameid_format . '"/></samlp:AuthnRequest>';

		Debug_Logger::log( '[SAML Request] Generated with ID: ' . $saml_request_id . ', Destination: ' . $destination );
		Debug_Logger::log( '[SAML Request] Issuer: ' . $issuer );
		return $this->encode_saml_request( $request_xml_str, $saml_request_dto->get_idp_details()->sso_binding );
	}

	/**
	 * Encodes the SAML request string.
	 *
	 * @param string $request_xml_str The SAML request string.
	 * @param string $binding_type The binding type (HttpRedirect or HttpPost).
	 * @return string The encoded SAML request.
	 */
	private function encode_saml_request( $request_xml_str, $binding_type = 'HttpRedirect' ) {
		$deflated_str = gzdeflate( $request_xml_str );
		//phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode -- Require to encode the SAML request.
		$base64_encoded_str = base64_encode( $deflated_str );

		if ( 'HttpPost' === $binding_type ) {
			return $request_xml_str;
		}

		//phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.urlencode_urlencode -- Require when encoding string to be used in query part of URL.
		$url_encoded = urlencode( $base64_encoded_str );
		return $url_encoded;
	}
}
