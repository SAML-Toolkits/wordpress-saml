<?php
/**
 * Init Controller.
 *
 * @package MOSAML\SRC\Controller
 */

namespace MOSAML\SRC\Controller;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\SRC\DTO\SAML_Response_DTO;
use MOSAML\SRC\Handler\Exception_Handler;
use MOSAML\Traits\Instance;
use MOSAML\SRC\Constant\Plugin_Options;
use MOSAML\SRC\DTO\SAML_Request_DTO;
use MOSAML\SRC\Utils\Utility;
use MOSAML\SRC\Utils\Error_Success_Message;
use MOSAML\SRC\Constant\Error_Codes_Enums;
use MOSAML\SRC\Exception\Invalid_XML_Exception;
use MOSAML\SRC\Exception\DOM_Extension_Disabled_Exception;
use MOSAML\SRC\Exception\Invalid_Assertion_Exception;
use MOSAML\SRC\Exception\Encrypted_Assertion_Exception;
use MOSAML\SRC\Exception\Invalid_Status_Code_Exception;
use MOSAML\SRC\Exception\SP_Clock_Behind_Of_IDP_Clock_Exception;
use MOSAML\SRC\Exception\SP_Clock_Ahead_Of_IDP_Clock_Exception;
use MOSAML\SRC\Exception\Cert_Mismatch_Exception;
use MOSAML\SRC\Exception\Cert_Mismatch_Encoding_Exception;
use MOSAML\SRC\Exception\Invalid_Entity_ID_Exception;
use MOSAML\SRC\Exception\Signature_Not_Found_Exception;
use MOSAML\SRC\Exception\Invalid_Audience_URI_Exception;
use MOSAML\SRC\Exception\CURL_Extension_Disabled_Exception;
use MOSAML\SRC\Exception\OpenSSL_Extension_Disabled_Exception;
use MOSAML\SRC\Exception\IDP_Not_Present_At_SP_Exception;
use MOSAML\SRC\Exception\IDP_Status_Inactive_Exception;
use MOSAML\SRC\Exception\Element_Decryption_Exception;
use MOSAML\SRC\Exception\Duplicate_SAML_Response_Exception;
use MOSAML\SRC\Exception\User_Creation_Failed_Exception;
use MOSAML\SRC\Exception\Blacklisted_User_Exception;
use MOSAML\SRC\Exception\Non_Whitelisted_User_Exception;
use MOSAML\SRC\Exception\Username_Too_Large_Exception;
use MOSAML\SRC\Exception\Non_WP_Member_Exception;
use Exception;
use MOSAML\SRC\Exception\Invalid_License_Exception;
use MOSAML\SRC\Utils\Feature_Control;
use MOSAML\SRC\Utils\DB_Utils;
use MOSAML\SRC\Constant\Constants;
use MOSAML\SRC\Constant\Plugin_Files_Constants;
use MOSAML\SRC\Exception\Attribute_Restriction_Exception;

/**
 * Init Controller.
 *
 * This class handles the initialization of SAML SSO actions, including sending SAML requests and handling SAML responses.
 */
class Init_Controller {

	use Instance;

	/**
	 * Handles the initialization actions for SAML SSO.
	 * Checks for SAML request or response options in the request and processes accordingly.
	 *
	 * @return void
	 */
	public function init_actions() {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Nonce verification not required since we are dealing with request params here.
		$option = Utility::sanitize_request_data( 'option' );

		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Nonce verification not required since we are dealing with request params here.
		$is_metadata_request = isset( $_REQUEST['option'] ) && 'mosaml_metadata' === $_REQUEST['option'];

		if ( $is_metadata_request ) {
			if ( 1 !== MOSAML_VERSION && ! Feature_Control::check_is_license_verified() ) {
				return;
			}
			$handler = Utility::get_handler_object( 'sp_metadata_data', true, 'admin' );
			$handler->display_sp_metadata();
			exit;
		}

		if ( 1 !== MOSAML_VERSION && ! Feature_Control::check_is_license_verified() ) {
			return;
		}

		$domain_mapping_email = isset( $_GET['mo_saml_domain_mapping_email'] ) ? sanitize_email( wp_unslash( $_GET['mo_saml_domain_mapping_email'] ) ) : '';
		if ( '' !== $domain_mapping_email && ! Utility::mo_saml_is_user_logged_in() ) {
			$login_footer_action_data_handler = Utility::get_handler_object( 'login_footer_action_data', true, 'core' );
			$login_footer_action_data_handler->handle_domain_based_redirection( $domain_mapping_email );
		} elseif ( isset( $_GET['get_domain_mapping'] ) && 'true' === sanitize_text_field( wp_unslash( $_GET['get_domain_mapping'] ) ) ) {
			$login_footer_action_data_handler = Utility::get_handler_object( 'login_footer_action_data', true, 'core' );
			$domain_mapping_data              = $login_footer_action_data_handler->get_domain_mapping_idp();
			wp_send_json( $domain_mapping_data );
		}

		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Nonce verification not required since we are dealing with request params here.
		if ( ! empty( $option ) && in_array( $option, Plugin_Options::SAML_REQUEST_OPTION, true ) ) {

			$current_environment_name  = DB_Utils::get_environment_details( 'environment_name' );
			$selected_environment_name = DB_Utils::get_environment_details( 'environment_name', false );
			if ( Plugin_Options::SAML_REQUEST_OPTION['TEST_CONFIG'] === $option ) {
				$nonce = isset( $_REQUEST['_wpnonce'] ) ? sanitize_text_field( wp_unslash( $_REQUEST['_wpnonce'] ) ) : '';
				if ( ! wp_verify_nonce( $nonce, Plugin_Options::SAML_REQUEST_OPTION['TEST_CONFIG'] ) || ! current_user_can( 'manage_options' ) ) {
					wp_die( 'You are not authorized to access this page.' );
				}
				if ( $current_environment_name !== $selected_environment_name ) {
					require_once Plugin_Files_Constants::TEMPLATE_TEST_CONFIG_CURR_ENV_ERROR;
					exit;
				}
				$this->validate_idp_for_test_config( 'test configuration' );
			} elseif ( Plugin_Options::SAML_REQUEST_OPTION['END_USER_TEST_CONFIG'] === $option ) {
				if ( $current_environment_name !== $selected_environment_name ) {
					return;
				}
				$this->validate_idp_for_test_config( 'end user test configuration' );
			}

			try {
				$saml_request_dto = new SAML_Request_DTO();
				$handler          = Utility::get_handler_object( 'saml_request', true, 'saml' );
				$this->get_idp_details_from_params( $saml_request_dto );

				$missing = Utility::check_required_extensions();
				if ( ! empty( $missing ) ) {
					$e = Utility::create_extension_disabled_exception( $missing[0] );
					if ( $e ) {
						Exception_Handler::throw_exception( $e );
					}
					return;
				}

				if ( ! is_user_logged_in() || Utility::is_test_configuration_request() ) {
					$handler->handle_saml_request( $saml_request_dto );
					if ( session_status() === PHP_SESSION_NONE ) {
						session_start();
					}
					$_SESSION['mosaml_login_idp_id'] = $saml_request_dto->get_idp_details()->idp_id;
					header( 'cache-control: max-age=0, private, no-store, no-cache, must-revalidate' );
					header( 'Location: ' . $saml_request_dto->get_redirect() );
					exit();
				} else {
					$redirect_to = Utility::sanitize_request_data( 'redirect_to' );
					$send_relay_state = is_array( $redirect_to ) ? $redirect_to[0] : $redirect_to;
					if ( empty( $send_relay_state ) ) {
						$send_relay_state = home_url() . '/';
					}
					wp_safe_redirect( $send_relay_state );
					exit();
				}
			} catch ( IDP_Not_Present_At_SP_Exception $e ) {
				Exception_Handler::throw_exception( $e );
			} catch ( IDP_Status_Inactive_Exception $e ) {
				Exception_Handler::throw_exception( $e );
			} catch ( Invalid_License_Exception $ex ) {
				Exception_Handler::throw_exception( $ex );
			}
		}

		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Nonce verification not required since we are dealing with request params here.
		if ( ! empty( $_REQUEST[ Plugin_Options::SAML_REQUEST ] ) ) {
			try {
				$missing = Utility::check_required_extensions();
				if ( ! empty( $missing ) ) {
					$e = Utility::create_extension_disabled_exception( $missing[0] );
					if ( $e ) {
						Exception_Handler::throw_exception( $e );
					}
					return;
				}
				$saml_request_dto = new SAML_Request_DTO();
				$saml_request_dto->set_saml_request( Utility::sanitize_request_data( Plugin_Options::SAML_REQUEST ) );
				$relay_state = Utility::sanitize_relay_state_request();
				$relay_state = ( '' !== $relay_state ) ? $relay_state : '/';

				$saml_request_dto->set_relay_state( $relay_state );
				( Utility::get_handler_object( 'saml_request', true, 'saml' ) )->handle_saml_request( $saml_request_dto );
			} catch ( Invalid_XML_Exception $ex ) {
				Exception_Handler::throw_exception( $ex );
			} catch ( Invalid_Assertion_Exception $ex ) {
				Exception_Handler::throw_exception( $ex );
			} catch ( Invalid_License_Exception $ex ) {
				Exception_Handler::throw_exception( $ex );
			}
		}

        // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Nonce verification not required since we are dealing with request params here.
		if ( isset( $_REQUEST[ Plugin_Options::SAML_RESPONSE_OPTION['SAML_RESPONSE'] ] ) ) {
			try {
				$missing = Utility::check_required_extensions();
				if ( ! empty( $missing ) ) {
					$e = Utility::create_extension_disabled_exception( $missing[0] );
					if ( $e ) {
						Exception_Handler::throw_exception( $e );
					}
					return;
				}
				$this->handle_saml_response();
			} catch ( Invalid_XML_Exception $ex ) {
				Exception_Handler::throw_exception( $ex );
			} catch ( Invalid_Assertion_Exception $ex ) {
				Exception_Handler::throw_exception( $ex );
			} catch ( Encrypted_Assertion_Exception $ex ) {
				Exception_Handler::throw_exception( $ex );
			} catch ( Invalid_Status_Code_Exception $ex ) {
				Exception_Handler::throw_exception( $ex );
			} catch ( SP_Clock_Behind_Of_IDP_Clock_Exception $ex ) {
				Exception_Handler::throw_exception( $ex );
			} catch ( SP_Clock_Ahead_Of_IDP_Clock_Exception $ex ) {
				Exception_Handler::throw_exception( $ex );
			} catch ( Signature_Not_Found_Exception $ex ) {
				Exception_Handler::throw_exception( $ex );
			} catch ( Cert_Mismatch_Exception $ex ) {
				Exception_Handler::throw_exception( $ex );
			} catch ( Cert_Mismatch_Encoding_Exception $ex ) {
				Exception_Handler::throw_exception( $ex );
			} catch ( Invalid_Entity_ID_Exception $ex ) {
				Exception_Handler::throw_exception( $ex );
			} catch ( Invalid_Audience_URI_Exception $ex ) {
				Exception_Handler::throw_exception( $ex );
			} catch ( Element_Decryption_Exception $ex ) {
				Exception_Handler::throw_exception( $ex );
			} catch ( Invalid_License_Exception $ex ) {
				Exception_Handler::throw_exception( $ex );
			} catch ( IDP_Not_Present_At_SP_Exception $ex ) {
				Exception_Handler::throw_exception( $ex );
			} catch ( Duplicate_SAML_Response_Exception $ex ) {
				Exception_Handler::throw_exception( $ex );
			} catch ( User_Creation_Failed_Exception $ex ) {
				Exception_Handler::throw_exception( $ex );
			} catch ( Username_Too_Large_Exception $ex ) {
				Exception_Handler::throw_exception( $ex );
			} catch ( Non_WP_Member_Exception $ex ) {
				Exception_Handler::throw_exception( $ex );
			} catch ( Blacklisted_User_Exception $ex ) {
				Exception_Handler::throw_exception( $ex );
			} catch ( Non_Whitelisted_User_Exception $ex ) {
				Exception_Handler::throw_exception( $ex );
			} catch ( Attribute_Restriction_Exception $ex ) {
				Exception_Handler::throw_exception( $ex );
			} catch ( Exception $ex ) {
				wp_die( '<b>[' . esc_attr( Error_Codes_Enums::$error_codes['WPSAMLERR028']['code'] ) . ']</b> ' . esc_attr( Error_Codes_Enums::$error_codes['WPSAMLERR028']['cause'] ) );
			}
		}
	}

	/**
	 * Init CLI actions.
	 *
	 * @return void
	 */
	public function init_cli_actions() {
		if ( defined( 'WP_CLI' ) && WP_CLI ) {
			if ( file_exists( Plugin_Files_Constants::MODULE_PREMIUM_CLI ) ) {
				require_once Plugin_Files_Constants::MODULE_PREMIUM_CLI;
			}
		}
	}

	/**
	 * Handles the SAML response controller.
	 *
	 * @return void
	 * @throws Invalid_XML_Exception If the SAML response is empty.
	 * @throws Invalid_License_Exception If the license is invalid.
	 */
	private function handle_saml_response() {
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Nonce verification not required since we are dealing with request params here.
		if ( empty( $_REQUEST[ Plugin_Options::SAML_RESPONSE_OPTION['SAML_RESPONSE'] ] ) ) {
			throw new Invalid_XML_Exception( 'Empty SAML response received' );
		}

        // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Nonce verification not required since we are dealing with request params here.
		$saml_response = Utility::sanitize_request_data( Plugin_Options::SAML_RESPONSE_OPTION['SAML_RESPONSE'] );

		$saml_response_dto = new SAML_Response_DTO();
		( Utility::get_handler_object( 'saml_response', true, 'saml' ) )->handle_saml_response( $saml_response_dto, $saml_response );
		
		$relay_state = Utility::sanitize_relay_state_request();

		$saml_response_dto->set_relay_state( $relay_state );

		if ( $saml_response_dto->get_logout_response() ) {

			if ( 1 !== MOSAML_VERSION && ! Feature_Control::check_is_license_valid() ) {
				throw new Invalid_License_Exception( 'Invalid License' );
			}

			$idp_issuer  = ! empty( $saml_response_dto->get_issuer() ) ? $saml_response_dto->get_issuer() : $saml_response_dto->get_current_assertion()->get_issuer();
			$idp_details = ( Utility::get_handler_object( 'sp_setup_data', true, 'admin' ) )->get_data( array( 'entity_id' => $idp_issuer, 'environment_id' => DB_Utils::get_environment_details( 'id' ) ) );
			$idp_id      = isset( $idp_details->id ) ? $idp_details->id : null;
			if ( ! is_null( $idp_id ) ) {
				$relay_state_handler = Utility::get_handler_object( 'relay_state_data', true, 'admin' );
				$relay_state_data    = $relay_state_handler->get_data( array( 'idp_id' => $idp_id ) );

				if ( ! empty( $relay_state_data->logout_relay_state ) ) {
					$relay_state = $relay_state_data->logout_relay_state;
				}
			}
			( Utility::get_handler_object( 'user_logout', true ) )->handle_logout( $relay_state );
		} elseif ( Plugin_Options::SAML_REQUEST_OPTION['TEST_CONFIG'] === $relay_state || Plugin_Options::SAML_REQUEST_OPTION['END_USER_TEST_CONFIG'] === $relay_state ) {

			$end_user_test                      = Plugin_Options::SAML_REQUEST_OPTION['END_USER_TEST_CONFIG'] === $relay_state;
			$name_id                            = $saml_response_dto->get_assertions()[0]->get_name_id();
			$idp_attributes                     = $saml_response_dto->get_assertions()[0]->get_attributes();
			$idp_attributes['NameID']           = $name_id;
			$idp_attributes['sanitize_further'] = true;
			/* Filter to modify and sanitize SAML attributes received in the SAML Response.
			 *
			 * This filter allows you to adjust the SAML attributes before they are used for login.
			 * To finalize custom sanitization, set the 'sanitize_further' key in the $attrs array to false
			 * and return the modified attributes.
			 *
			 * @since 25.2.8
			 *
			 * @param array $attrs The SAML attributes received in the response.
			 * @return array Filtered and sanitized attributes.
			 */
			// phpcs:ignoreFile WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- Already added filter.
			$idp_attributes           = apply_filters( 'mo_saml_sanitize_attributes', $idp_attributes );
			$redirect_url             = Utility::get_tab_url( 'attribute_role_mapping', '', $saml_response_dto->get_idp_pk() );
			$redirect_button_text     = 'Configure Attribute/Role Mapping';
			Utility::update_test_config_attributes( $idp_attributes, $saml_response_dto->get_idp_pk() );
			if ( ! empty( $saml_response_dto->get_idp_pk() ) && ! empty( $saml_response ) ) {
				DB_Utils::insert_or_update(
					Constants::DATABASE_TABLE_NAMES['idp_details'],
					array( 'saml_response' => $saml_response ),
					array(
						'id'             => $saml_response_dto->get_idp_pk(),
						'environment_id' => DB_Utils::get_environment_details( 'id', false ),
					)
				);
			}

			if ( $end_user_test && ! empty( $saml_response ) ) {
				if ( session_status() === PHP_SESSION_NONE ) {
					session_start();
				}
				$_SESSION['mo_saml_end_user_test_saml_response'] = $saml_response;
			}

			Error_Success_Message::show_test_config_window( $end_user_test, $idp_attributes, $redirect_url, $redirect_button_text, $saml_response_dto->get_idp_details()->idp_id );
		} else {
			Utility::get_handler_object( 'user_login', false, 'core' )->handle_login( $saml_response_dto );
		}
	}

	/**
	 * Get the IDP details from request param.
	 *
	 * @param SAML_Request_DTO $saml_request_dto The SAML request DTO.
	 * @return void
	 * @throws IDP_Not_Present_At_SP_Exception If the IDP is not present at the SP.
	 * @throws IDP_Status_Inactive_Exception If the IDP is not active.
	 */
	private function get_idp_details_from_params( $saml_request_dto ) {
		$environment_id = DB_Utils::get_environment_details( 'id' );

		if ( Utility::is_legacy_data_fallback_required() ) {
			$where               = array(
				'environment_id' => $environment_id,
				'default_idp'    => true,
			);
			$default_idp_details = apply_filters( 'mosaml_legacy_data_fallback_object', Utility::get_handler_object( 'sp_setup_data', true, 'admin' ), $where );
			$default_idp_id      = $default_idp_details->idp_id;
		} else {
			$default_idp_details = Utility::get_default_idp( $environment_id );
			$default_idp_id      = $default_idp_details ? $default_idp_details->idp_id : '';
		}

		$idp_id      = Utility::sanitize_request_data( 'idp', false, $default_idp_id );
		$idp_details = Utility::get_idp_details_from_idp_id( $idp_id, $environment_id );

		if ( is_null( $idp_details ) || empty( $idp_details->idp_name ) ) {
			throw new IDP_Not_Present_At_SP_Exception( 'IDP not found' );
		}

		if ( 'All IDPs' === $idp_details->idp_name ) {
			throw new IDP_Not_Present_At_SP_Exception( 'IDP not present at SP' );
		}

		if ( 'active' !== $idp_details->status ) {
			throw new IDP_Status_Inactive_Exception( 'IDP is not enabled' );
		}

		$saml_request_dto->set_idp_details( $idp_details );
	}

	/**
	 * Validate IDP for test configuration.
	 *
	 * @param string $config_type The type of test configuration (e.g., 'test configuration' or 'end user test configuration').
	 * @return void
	 */
	private function validate_idp_for_test_config( $config_type ) {
		$idp_id = Utility::sanitize_request_data( 'idp' );
		if ( empty( $idp_id ) ) {
			wp_die( sprintf( 'IDP ID is required for %s.', esc_html( $config_type ) ) );
		}

		$environment_id = DB_Utils::get_environment_details( 'id' );
		$idp_details    = Utility::get_idp_details_from_idp_id( $idp_id, $environment_id );

		if ( empty( $idp_details ) || empty( $idp_details->idp_id ) || empty( $idp_details->idp_name ) ) {
			wp_die( 'Invalid IDP ID. Please ensure the IDP is configured and saved before testing.' );
		}

		if ( 'All IDPs' === $idp_details->idp_name ) {
			wp_die( sprintf( '%s is not available for "All IDPs". Please select a specific IDP.', esc_html( ucfirst( $config_type ) ) ) );
		}
	}

	/**
	 * Control license expiry page.
	 *
	 * @return void
	 */
	public function control_license_expiry_page() {
		if ( 1 === MOSAML_VERSION ) {
			return;
		}
		$license_expiry_page_handler = Utility::get_handler_object( 'license_expiry_page', false, '' );
		$license_expiry_page_handler->handle_license_expiry_page();
	}
}
