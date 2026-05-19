<?php
/**
 * User Logout Handler file for Premium Version.
 *
 * @package MOSAML\Module\Premium\Handler
 */

namespace MOSAML\Module\Premium\Handler;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\Module\Standard\Handler\User_Logout_Handler as Standard_User_Logout_Handler;
use MOSAML\SRC\Utils\Utility;
use MOSAML\SRC\Utils\XML_Utility;
use MOSAML\SRC\Constant\Constants;
use MOSAML\SRC\DTO\SAML_Request_DTO;
use RobRichards\XMLSecLibs\XMLSecurityKey;

/**
 * User Logout Handler for Premium Version.
 *
 * This class handles the user logout process.
 */
class User_Logout_Handler extends Standard_User_Logout_Handler {

	/**
	 * Create the logout request and redirect to the IDP logout URL.
	 *
	 * @param SAML_Request_DTO $saml_request_dto SAML request DTO.
	 * @param int              $user_id The user ID.
	 * @return void
	 */
	public function create_logout_request_and_redirect( $saml_request_dto, $user_id ) {

		$name_id = $this->get_name_id( $user_id );

		if ( ! empty( $name_id ) ) {
			Utility::delete_plugin_session_and_cookies();
		}

		$sp_base_url = ! empty( $saml_request_dto->get_sp_details()->sp_base_url ) ? $saml_request_dto->get_sp_details()->sp_base_url : network_home_url();
		$relay_state = $this->get_relay_state( $sp_base_url );
		if ( '/' === substr( $sp_base_url, - 1 ) ) {
			$sp_base_url = substr( $sp_base_url, 0, - 1 );
		}
		$sp_entity_id = ! empty( $saml_request_dto->get_idp_details()->sp_entity_id ) ? $saml_request_dto->get_idp_details()->sp_entity_id : ( ! empty( $saml_request_dto->get_sp_details()->entity_id ) ? $saml_request_dto->get_sp_details()->entity_id : $sp_base_url . Constants::SP_ENTITY_ID );
		$destination  = ! empty( $saml_request_dto->get_idp_details()->slo_response_url ) ? $saml_request_dto->get_idp_details()->slo_response_url : $saml_request_dto->get_idp_details()->slo_url;

		$session_index  = $this->get_session_index( $user_id );
		$name_id_format = $saml_request_dto->get_idp_details()->name_id_format;

		$binding_type = $saml_request_dto->get_idp_details()->slo_binding;

		$logout_request = $this->create_logout_request( $name_id, $sp_entity_id, $destination, $binding_type, $session_index, $name_id_format );

		$this->handle_sp_initiated_logout( $logout_request, $saml_request_dto, $binding_type, $destination, $relay_state );
	}

	/**
	 * Logout the user from WordPress.
	 *
	 * @return void
	 */
	private function logout_wordpress_user() {
		if ( Utility::mo_saml_is_user_logged_in() ) {
			wp_destroy_current_session();
			wp_clear_auth_cookie();
			wp_set_current_user( 0 );
		}
	}

	/**
	 * FUnction to handle the SP initiated logout flow on the basis of binding the signature attached to the request.
	 *
	 * @param string           $request Request Parameter.
	 * @param SAML_Request_DTO $saml_request_dto SAML request DTO.
	 * @param string           $binding_type Binding type for the request.
	 * @param string           $destination Destination for the request.
	 * @param string           $relay_state Relay state parameter.
	 *
	 * @return void
	 */
	public function handle_sp_initiated_logout( $request, $saml_request_dto, $binding_type, $destination, $relay_state ) {

		if ( empty( $binding_type ) || 'HttpRedirect' === $binding_type ) {

			$query_params = array(
				'SAMLRequest' => $request,
				'RelayState'  => rawurlencode( $relay_state ),
			);

			$redirect = add_query_arg( $query_params, $destination );

			if ( 'checked' === $saml_request_dto->get_idp_details()->sign_sso_slo_request ) {
				$param          = array( 'type' => 'private' );
				$key            = new XMLSecurityKey( XMLSecurityKey::RSA_SHA256, $param );
				$cert_file_path = ( $saml_request_dto->get_sp_certificates() )->private_key;
				$key->loadKey( $cert_file_path, false );

				$sig_request      = add_query_arg( array( 'SigAlg' => rawurlencode( XMLSecurityKey::RSA_SHA256 ) ), $redirect );
				$saml_request_str = wp_parse_url( $sig_request, PHP_URL_QUERY );
				$signature        = $key->signData( $saml_request_str );
				// PHPCS:IGNORE WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode -- Encoding the signature to sign Data.
				$signature = base64_encode( $signature );
				$redirect  = add_query_arg( array( 'Signature' => rawurlencode( $signature ) ), $sig_request );
			}

			// Logout the user from WordPress after sending logout request to IDP.
			$this->logout_wordpress_user();

			header( 'cache-control: max-age=0, private, no-store, no-cache, must-revalidate' );
			header( 'Location: ' . $redirect );
			exit();
		} else {
			if ( 'checked' === $saml_request_dto->get_idp_details()->sign_sso_slo_request ) {
				$request = XML_Utility::sign_xml( $request, $saml_request_dto, 'Status' );
			} else {
				// PHPCS:Ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode -- Encoding the XML to base64.
				$request = base64_encode( $request );
			}

			// Logout the user from WordPress after sending logout request to IDP.
			$this->logout_wordpress_user();

			$this->post_saml_request( $destination, $request, $relay_state );
			exit();
		}
	}

	/**
	 * Get the name ID.
	 *
	 * @param int $user_id The user ID.
	 * @return string
	 */
	private function get_name_id( $user_id ) {

		$name_id = '';

		if ( isset( $_SESSION['mo_guest_login']['nameID'] ) ) {
			$name_id = sanitize_text_field( $_SESSION['mo_guest_login']['nameID'] );
		} elseif ( isset( $_COOKIE['nameID'] ) ) {
			$name_id = sanitize_text_field( wp_unslash( $_COOKIE['nameID'] ) );
		} else {
			$name_id = get_user_meta( $user_id, 'mo_saml_name_id', true );
			delete_user_meta( $user_id, 'mo_saml_name_id' );
		}

		return $name_id;
	}

	/**
	 * Get the session index.
	 *
	 * @param int $user_id The user ID.
	 * @return string
	 */
	public function get_session_index( $user_id ) {

		$session_index = '';

		if ( isset( $_SESSION['mo_guest_login']['sessionIndex'] ) ) {
			$session_index = sanitize_text_field( $_SESSION['mo_guest_login']['sessionIndex'] );
		} elseif ( isset( $_COOKIE['sessionIndex'] ) ) {
			$session_index = sanitize_text_field( wp_unslash( $_COOKIE['sessionIndex'] ) );
		} else {
			$session_index = get_user_meta( $user_id, 'mo_saml_session_index', true );
			delete_user_meta( $user_id, 'mo_saml_session_index' );
		}

		return $session_index;
	}

	/**
	 * Create the logout request.
	 *
	 * @param string $name_id The name ID.
	 * @param string $issuer The issuer.
	 * @param string $destination The destination.
	 * @param string $slo_binding_type The SLO binding type.
	 * @param string $session_index The session index.
	 * @param string $saml_nameid_format The SAML name ID format.
	 * @return string
	 */
	public function create_logout_request( $name_id, $issuer, $destination, $slo_binding_type = 'HttpRedirect', $session_index = 'unspecified', $saml_nameid_format = '' ) {

		$request_xml_str = '<?xml version="1.0" encoding="UTF-8"?>' .
			'<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="' . Utility::generate_id() .
			'" IssueInstant="' . Utility::generate_time_stamp() .
			'" Version="2.0" Destination="' . $destination . '">
						<saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">' . $issuer . '</saml:Issuer>
						<saml:NameID xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" Format="' . $saml_nameid_format . '">' . $name_id . '</saml:NameID>';
		if ( ! empty( $session_index ) ) {
			$request_xml_str .= '<samlp:SessionIndex>' . $session_index . '</samlp:SessionIndex>';
		}
		$request_xml_str .= '</samlp:LogoutRequest>';

		if ( empty( $slo_binding_type ) || 'HttpRedirect' === $slo_binding_type ) {
			$deflated_str = gzdeflate( $request_xml_str );
			// PHPCS:Ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode -- Encoding the XML to base64.
			$base64_encoded_str = base64_encode( $deflated_str );
			$request_xml_str    = rawurlencode( $base64_encoded_str );
		}
		return $request_xml_str;
	}

	/**
	 * Posts the SAMLRequest if HTTPS POST binding is selected.
	 *
	 * @param string $url sso url.
	 * @param string $saml_request_xml encoded SAMLRequest.
	 * @param string $relay_state relayState Url.
	 * @param array  $request_array $_REQUEST Object.
	 * @param bool   $saml_request_email is uname/email in saml request.
	 * @return void
	 */
	public function post_saml_request( $url, $saml_request_xml, $relay_state, $request_array = array(), $saml_request_email = false ) {
		while ( ob_get_level() ) {
			ob_end_clean();
		}
		header_remove();

		$relay_state = is_string( $relay_state ) ? $relay_state : '/';
		echo '
        <html>
            <body>
                Please wait...
                <form action="' . esc_url( $url ) . '" method="post" id="saml-request-form">
                    <input type="hidden" name="SAMLRequest" value="' . esc_attr( $saml_request_xml ) . '" />
                    <input type="hidden" name="RelayState" value="' . esc_attr( $relay_state ) . '" />';
		foreach ( $request_array as $key => $value ) {
			if ( 'option' !== $key ) {
				echo '<input type="hidden" name="' . esc_attr( $key ) . '" value="' . esc_attr( $value ) . '" />';
			}
		}
		if ( is_string( $saml_request_email ) ) {
			echo '<input type="hidden" name="Email" value="' . esc_attr( $saml_request_email ) . '" />';
		}
				echo '
                </form>
                <script>
                    document.getElementById(\'saml-request-form\').submit();
                </script>
            </body>
        </html>';
	}

	/**
	 * Create the logout response and redirect to the IDP logout URL.
	 *
	 * @param SAML_Request_DTO $saml_request_dto SAML request DTO.
	 * @return void
	 */
	public function create_logout_response_and_redirect( $saml_request_dto ) {

		$sp_base_url = ! empty( $saml_request_dto->get_sp_details()->sp_base_url ) ? $saml_request_dto->get_sp_details()->sp_base_url : home_url();
		$relay_state = null;
		$idp_id      = $saml_request_dto->get_idp_details() && isset( $saml_request_dto->get_idp_details()->id ) ? $saml_request_dto->get_idp_details()->id : null;

		$relay_state_handler = Utility::get_handler_object( 'relay_state_data', true, 'admin' );

		// First, check for logout relay state for the specific IDP.
		if ( ! is_null( $idp_id ) ) {
			$relay_state_data = $relay_state_handler->get_data( array( 'idp_id' => $idp_id ) );

			if ( ! empty( $relay_state_data->logout_relay_state ) ) {
				$relay_state = $relay_state_data->logout_relay_state;
			}
		}

		// If not set for specific IDP, check for "All IDPs" logout relay state.
		if ( empty( $relay_state ) ) {
			$all_idps_idp = Utility::get_all_idps_idp();
			if ( ! is_null( $all_idps_idp ) && isset( $all_idps_idp->id ) ) {
				$all_idps_relay_state_data = $relay_state_handler->get_data( array( 'idp_id' => $all_idps_idp->id ) );

				if ( ! empty( $all_idps_relay_state_data->logout_relay_state ) ) {
					$relay_state = $all_idps_relay_state_data->logout_relay_state;
				}
			}
		}

		// If still not set, use relay state from get_relay_state() or session.
		if ( empty( $relay_state ) ) {
			$relay_state = $this->get_relay_state( $sp_base_url );
			$relay_state = ! empty( $relay_state ) ? $relay_state : ( isset( $_SESSION['mo_saml_logout_relay_state'] ) ? sanitize_text_field( $_SESSION['mo_saml_logout_relay_state'] ) : '/' );
		}

		if ( ! empty( $relay_state ) && ( ( filter_var( $relay_state, FILTER_VALIDATE_URL ) ) || wp_parse_url( home_url(), PHP_URL_HOST ) === wp_parse_url( $relay_state, PHP_URL_HOST ) ) ) {
			wp_safe_redirect( $relay_state );
		} else {
			wp_safe_redirect( $sp_base_url );
		}

		$logout_url   = ! empty( $saml_request_dto->get_idp_details()->slo_response_url ) ? $saml_request_dto->get_idp_details()->slo_response_url : $saml_request_dto->get_idp_details()->slo_url;
		$sp_entity_id = ! empty( $saml_request_dto->get_idp_details()->sp_entity_id ) ? $saml_request_dto->get_idp_details()->sp_entity_id : ( ! empty( $saml_request_dto->get_sp_details()->sp_entity_id ) ? $saml_request_dto->get_sp_details()->sp_entity_id : $sp_base_url . Constants::SP_ENTITY_ID );

		$logout_response = $this->create_logout_response( $saml_request_dto->get_request_id(), $sp_entity_id, $logout_url, $saml_request_dto->get_idp_details()->slo_binding );

		unset( $_SESSION['mo_saml_logout_request'], $_SESSION['mo_saml_logout_relay_state'] );
		Utility::delete_plugin_session_and_cookies();

		if ( empty( $saml_request_dto->get_idp_details()->slo_binding ) || 'HttpRedirect' === $saml_request_dto->get_idp_details()->slo_binding ) {

			$query_params = array(
				'SAMLResponse' => $logout_response,
				'RelayState'   => rawurlencode( $relay_state ),
			);

			$redirect = add_query_arg( $query_params, $logout_url );
			header( 'cache-control: max-age=0, private, no-store, no-cache, must-revalidate' );
			header( 'Location: ' . $redirect );
			exit();
		} else {
			if ( 'checked' === $saml_request_dto->get_idp_details()->sign_sso_slo_request ) {
				$logout_response = XML_Utility::sign_xml( $logout_response, $saml_request_dto, 'Status' );
			} else {
				// PHPCS:Ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode -- Encoding the XML to base64.
				$logout_response = base64_encode( $logout_response );
			}
			$this->post_saml_response( $logout_url, $logout_response, $relay_state );
			exit();
		}
	}

	/**
	 * Get the relay state for logout request.
	 *
	 * @param string $sp_base_url SP base URL.
	 *
	 * @return string
	 */
	public function get_relay_state( $sp_base_url ) {

		//phpcs:ignore WordPress.Security.NonceVerification.Recommended -- SSO redirect parameter, nonce not required.
		if ( ! empty( $_REQUEST['redirect_to'] ) ) {
			//phpcs:ignore WordPress.Security.NonceVerification.Recommended, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized, WordPress.Security.ValidatedSanitizedInput.MissingUnslash -- SSO redirect parameter, nonce not required.
			$relay_state = Utility::mo_saml_is_array( $_REQUEST['redirect_to'] );
		} else {
			$relay_state = wp_get_referer();
		}

		if ( empty( $relay_state ) ) {
			$relay_state = $sp_base_url;
		} 

		if ( ! empty( $relay_state ) ) {
			$relay_state_path  = wp_parse_url( $relay_state, PHP_URL_PATH );
			$relay_state_query = wp_parse_url( $relay_state, PHP_URL_QUERY );
		}

		$relay_state_path = empty( $relay_state_path ) ? '/' : $relay_state_path;

		if ( ! empty( $relay_state_query ) ) {
			$relay_state = $relay_state_path . '?' . $relay_state_query;
		} else {
			$relay_state = $relay_state_path;
		}

		/**
		 * Filter to change the relay state sent in SAML Logout Request
		 *
		 * @param string  $relay_state
		 */
		$relay_state = apply_filters( 'mosaml_pre_logout_slo_relay_state_internal', $relay_state );

		return $relay_state;
	}

	/**
	 * Create the logout response.
	 *
	 * @param string $in_response_to The InResponseTo attribute value.
	 * @param string $issuer The Issuer attribute value.
	 * @param string $destination The Destination attribute value.
	 * @param string $slo_binding_type The SLO binding type.
	 * @return string
	 */
	public function create_logout_response( $in_response_to, $issuer, $destination, $slo_binding_type = 'HttpRedirect' ) {

		$request_xml_str = '<?xml version="1.0" encoding="UTF-8"?>' .
			'<samlp:LogoutResponse xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ' .
			'ID="' . Utility::generate_id() . '" ' .
			'Version="2.0" IssueInstant="' . Utility::generate_time_stamp() . '" ' .
			'Destination="' . $destination . '" ' .
			'InResponseTo="' . $in_response_to . '">' .
			'<saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">' . $issuer . '</saml:Issuer>' .
			'<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status></samlp:LogoutResponse>';

		if ( empty( $slo_binding_type ) || 'HttpRedirect' === $slo_binding_type ) {
			$deflated_str = gzdeflate( $request_xml_str );
			// PHPCS:Ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode -- Encoding the XML to base64.
			$base64_encoded_str = base64_encode( $deflated_str );
			$request_xml_str    = rawurlencode( $base64_encoded_str );
		}
		return $request_xml_str;
	}

	/**
	 * Post the SAML response in SAML Post binding.
	 *
	 * @param string $url The URL to post the SAML response to.
	 * @param string $logout_response_xml The SAML response XML.
	 * @param string $relay_state The relay state.
	 * @return void
	 */
	public function post_saml_response( $url, $logout_response_xml, $relay_state ) {
		echo '
        <html>
            <body>
                Please wait...
                <form action="' . esc_url( $url ) . '" method="post" id="saml-response-form"><input type="hidden" name="SAMLResponse" value="' . esc_attr( $logout_response_xml ) . '" />
                    <input type="hidden" name="RelayState" value="' . esc_attr( $relay_state ) . "\" />
                </form>
                <script>
                    document.getElementById('saml-response-form').submit();
                </script>
            </body>
        </html>";
		exit();
	}

	/**
	 * Handles the user logout process for premium version.
	 *
	 * @param string $relay_state The relay state.
	 * @param bool   $logout_via_hook Whether the logout is via hook.
	 *
	 * @return void
	 */
	public function handle_logout( $relay_state, $logout_via_hook = false ) {

		$idp_id = null;
		// Try to get IDP ID from user meta or session before logout.
		if ( Utility::mo_saml_is_user_logged_in() ) {
			$current_user = wp_get_current_user();
			if ( $current_user && $current_user->ID ) {
				$idp_id = get_user_meta( $current_user->ID, 'mo_saml_logged_in_with_idp', true );
			}
		}

		// If not found in user meta, try session.
		if ( empty( $idp_id ) && isset( $_SESSION['mo_saml']['logged_in_with_idp'] ) ) {
			$idp_id = sanitize_text_field( $_SESSION['mo_saml']['logged_in_with_idp'] );
		}

		$relay_state_handler = Utility::get_handler_object( 'relay_state_data', true, 'admin' );
		$final_relay_state   = $relay_state;

		// First, check for logout relay state for the specific IDP.
		if ( ! empty( $idp_id ) ) {
			$relay_state_data = $relay_state_handler->get_data( array( 'idp_id' => $idp_id ) );

			if ( ! empty( $relay_state_data->logout_relay_state ) ) {
				$final_relay_state = $relay_state_data->logout_relay_state;
			}
		}

		// If not set for specific IDP, check for "All IDPs" logout relay state.
		if ( empty( $final_relay_state ) ) {
			$all_idps_idp = Utility::get_all_idps_idp();
			if ( ! is_null( $all_idps_idp ) && isset( $all_idps_idp->id ) ) {
				$all_idps_relay_state_data = $relay_state_handler->get_data( array( 'idp_id' => $all_idps_idp->id ) );

				if ( ! empty( $all_idps_relay_state_data->logout_relay_state ) ) {
					$final_relay_state = $all_idps_relay_state_data->logout_relay_state;
				}
			}
		}

		// If still not set, use the provided relay state.
		if ( empty( $final_relay_state ) ) {
			//phpcs:ignore WordPress.Security.NonceVerification.Recommended -- SSO redirect parameter, nonce not required.
			if ( ! empty( $_REQUEST['redirect_to'] ) ) {
				//phpcs:ignore WordPress.Security.NonceVerification.Recommended, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized, WordPress.Security.ValidatedSanitizedInput.MissingUnslash -- SSO redirect parameter, nonce not required.
				$final_relay_state = Utility::mo_saml_is_array( $_REQUEST['redirect_to'] );
			} else {
				$final_relay_state = wp_get_referer();
			}

			if ( empty( $final_relay_state ) ) {
				$final_relay_state = $relay_state;
			}
		}

		if ( ! empty( $final_relay_state ) ) {
			$relay_state_path  = wp_parse_url( $final_relay_state, PHP_URL_PATH );
			$relay_state_query = wp_parse_url( $final_relay_state, PHP_URL_QUERY );
		}

		$relay_state_path = empty( $relay_state_path ) ? '/' : $relay_state_path;

		if ( ! empty( $relay_state_query ) ) {
			$final_relay_state = $relay_state_path . '?' . $relay_state_query;
		} else {
			$final_relay_state = $relay_state_path;
		}

		if ( $logout_via_hook ) {
			Utility::delete_plugin_session_and_cookies();
			wp_safe_redirect( $final_relay_state );
			exit;
		}

		$this->logout_wordpress_user();

		/**
		 * Filter to change the relay state after the SAML Logout Response.
		 *
		 * @param string $relay_state The relay state.
		 *
		 * @param string  $relay_state
		 */
		$final_relay_state = apply_filters( 'mosaml_post_logout_slo_relay_state_internal', $final_relay_state );

		wp_safe_redirect( $final_relay_state );
		exit;
	}
}
