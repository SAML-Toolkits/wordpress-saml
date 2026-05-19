<?php
/**
 * Logout Controller.
 *
 * @package MOSAML\SRC\Controller
 */

namespace MOSAML\SRC\Controller;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\SRC\Utils\Utility;
use MOSAML\Module\Base\Handler\Admin\SP_Endpoints_Data_Handler;
use MOSAML\SRC\DTO\SAML_Request_DTO;
use MOSAML\Module\Base\Handler\Admin\Certificate_Data_Handler;
use MOSAML\SRC\Exception\DOM_Extension_Disabled_Exception;
use MOSAML\SRC\Exception\CURL_Extension_Disabled_Exception;
use MOSAML\SRC\Exception\OpenSSL_Extension_Disabled_Exception;
use MOSAML\SRC\Exception\Invalid_XML_Exception;
use MOSAML\SRC\Exception\Invalid_Assertion_Exception;
use MOSAML\SRC\Handler\Exception_Handler;
use MOSAML\SRC\Utils\Feature_Control;

/**
 * Logout Controller class.
 *
 * This class controls the logout flow.
 */
class Logout_Controller {

	/**
	 * Control the logout flow.
	 *
	 * @param int    $user_id The user ID.
	 * @param string $redirect_to The redirect to.
	 * @return void
	 */
	public function control_logout_flow( $user_id, $redirect_to = '' ) {
		try {

			delete_user_meta( $user_id, 'mosaml_show_license_expiry_page' );
			if ( 1 !== MOSAML_VERSION && ! Feature_Control::check_is_license_valid() ) {
				return;
			}

			$missing = Utility::check_required_extensions();
			if ( ! empty( $missing ) ) {
				$e = Utility::create_extension_disabled_exception( $missing[0] );
				if ( $e ) {
					Exception_Handler::throw_exception( $e );
				}
				return;
			}
			Utility::start_session();

			$idp_index = Utility::get_idp_id_from_session();

			if ( empty( $idp_index ) ) {
				return;
			}

			$idp_details = Utility::get_handler_object( 'sp_setup_data', true, 'admin' )->get_data( array( 'id' => $idp_index ) );
			$sp_details  = ( new SP_Endpoints_Data_Handler() )->get_data();

			$sp_certificate_data_handler = new Certificate_Data_Handler();

			$saml_request_dto = new SAML_Request_DTO();
			if ( $idp_details->sp_certificate && $idp_details->sp_private_key ) {
				$sp_certificate_data_handler->public_key  = $idp_details->sp_certificate;
				$sp_certificate_data_handler->private_key = $idp_details->sp_private_key;
				$saml_request_dto->set_sp_certificates( $sp_certificate_data_handler );
			} else {
				$saml_request_dto->set_sp_certificates( $sp_certificate_data_handler->get_data() );
			}

			$saml_request_dto->set_idp_details( $idp_details );
			$saml_request_dto->set_sp_details( $sp_details );

			if ( empty( $idp_details ) || empty( $idp_details->slo_url ) ) {
				$sp_base_url = ! empty( $sp_details->sp_base_url ) ? $sp_details->sp_base_url : home_url();
				( Utility::get_handler_object( 'user_logout', true ) )->handle_logout( $sp_base_url, true );
				return;
			}

			if ( ! empty( $_SESSION['mo_saml_logout_request'] ) ) {
				$this->control_logout_response_flow( $saml_request_dto );
			}

			$this->control_logout_request_flow( $saml_request_dto, $user_id );
		} catch ( Invalid_XML_Exception $ex ) {
			Exception_Handler::throw_exception( $ex );
		} catch ( Invalid_Assertion_Exception $ex ) {
			Exception_Handler::throw_exception( $ex );
		}
	}

	/**
	 * Control the logout response flow when the Logout Request is received from the IDP.
	 *
	 * @param SAML_Request_DTO $saml_request_dto SAML request DTO.
	 * @return void
	 */
	public function control_logout_response_flow( $saml_request_dto ) {

		$logout_request = ! empty( $_SESSION['mo_saml_logout_request'] ) ? sanitize_text_field( $_SESSION['mo_saml_logout_request'] ) : '';
		$saml_request_dto->set_saml_request( $logout_request );

		$saml_request_handler = Utility::get_handler_object( 'saml_request', true, 'saml' );
		$saml_request_handler->set_dto_for_logout_request( $saml_request_dto );

		$logout_handler = Utility::get_handler_object( 'user_logout', true );
		$logout_handler->create_logout_response_and_redirect( $saml_request_dto );
	}

	/**
	 * Control the logout request flow when the Logout Request is received from the IDP.
	 *
	 * @param SAML_Request_DTO $saml_request_dto SAML request DTO.
	 * @param int              $user_id The user ID.
	 * @return void
	 */
	public function control_logout_request_flow( $saml_request_dto, $user_id ) {
		$logout_handler = Utility::get_handler_object( 'user_logout', true );
		$logout_handler->create_logout_request_and_redirect( $saml_request_dto, $user_id );
	}
}
