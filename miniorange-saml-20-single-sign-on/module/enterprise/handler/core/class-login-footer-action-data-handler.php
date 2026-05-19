<?php
/**
 * Login Footer Action Handler.
 *
 * @package MOSAML
 * @subpackage Module\Enterprise\Handler\Core
 */

namespace MOSAML\Module\Enterprise\Handler\Core;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\SRC\Constant\Constants;
use MOSAML\SRC\Constant\Plugin_Options;
use MOSAML\SRC\Handler\UI\Login_Page_UI_Handler;
use MOSAML\Module\Premium\Handler\Core\Login_Footer_Action_Data_Handler as Premium_Login_Footer_Action_Data_Handler;
use MOSAML\SRC\Utils\Utility;
use MOSAML\SRC\Utils\DB_Utils;

/**
 * Login Footer Action Handler.
 */
class Login_Footer_Action_Data_Handler extends Premium_Login_Footer_Action_Data_Handler {

	/**
	 * Load domain mapping SSO settings for the environment that matches this site URL (login / public), not the admin-selected environment.
	 *
	 * @return object Domain mapping handler data object.
	 */
	private function get_domain_mapping_data_for_current_environment() {
		$handler                = Utility::get_handler_object( 'domain_mapping_data', true, 'admin' );
		$current_environment_id = DB_Utils::get_environment_details( 'id', true );
		$default_idp_id         = DB_Utils::get_default_inserted_idp_details( 'id', $current_environment_id );

		return $handler->get_data(
			array(
				'idp_id'     => $default_idp_id,
				'subsite_id' => Utility::get_subsite_id_for_environment( $current_environment_id ),
			)
		);
	}

	/**
	 * Login footer actions.
	 *
	 * @return void
	 */
	public function login_footer_actions() {
		if ( ! wp_script_is( 'mosaml-login-js', 'enqueued' ) ) {
			wp_enqueue_script( 'mosaml-login-js', plugins_url( 'static/js/login.js', MOSAML_PLUGIN_FILE ), array(), Constants::VERSION_NUMBER[ MOSAML_VERSION ], true );
		}
		$domain_mapping_data = $this->get_domain_mapping_data_for_current_environment();

		$current_environment_id = DB_Utils::get_environment_details( 'id', true );
		$default_idp_id         = DB_Utils::get_default_inserted_idp_details( 'id', $current_environment_id );
		$hide_wp_login_object = Utility::get_handler_object( 'hide_wp_login_data', true, 'admin' )->get_data(
			array(
				'idp_id'     => $default_idp_id,
				'subsite_id' => Utility::get_subsite_id_for_environment( $current_environment_id ),
			)
		);

		$domain_mapping_enabled = $domain_mapping_data->enable_domain_mapping;
		if ( ! empty( $hide_wp_login_object ) && 'checked' === $hide_wp_login_object->hide_wp_login ) {
			$domain_mapping_enabled = '';
		}

		wp_localize_script(
			'mosaml-login-js',
			'moSamlLoginData',
			array(
				'domainMappingEnabled' => $domain_mapping_enabled,
				'ajaxUrl'              => admin_url( 'admin-ajax.php' ),
				'nonce'                => wp_create_nonce( 'mosaml_fetch_domain_mapping_ajax_nonce' ),
				'isBackdoorLogin'      => Login_Page_UI_Handler::is_backdoor_login(),
			)
		);
		parent::login_footer_actions();
	}

	/**
	 * Fetch domain mapping.
	 *
	 * @param string $user_email The user email.
	 * @param bool   $ajax Whether to return a JSON response.
	 * @return WP_Error|WP_REST_Response|string JSON response.
	 */
	public function fetch_domain_mapping( $user_email, $ajax = true ) {
		$domain_mapping_data = $this->get_domain_mapping_data_for_current_environment();

		if ( 'checked' !== $domain_mapping_data->enable_domain_mapping ) {
			if ( ! $ajax ) {
				return wp_json_encode(
					array(
						'success' => false,
						'data'    => 'Domain mapping not enabled',
						'code'    => 403,
					)
				);
			}
			return wp_send_json_error( 'Domain mapping not enabled', 403 );
		}
		$domain = Utility::get_domain_from_email( $user_email );
		if ( ! $domain ) {
			if ( ! $ajax ) {
				return wp_json_encode(
					array(
						'success' => false,
						'data'    => 'Invalid email address',
						'code'    => 400,
					)
				);
			}
			return wp_send_json_error( 'Invalid email address', 400 );
		}
		$idp_id_to_redirect = '';
		foreach ( $domain_mapping_data->domain_mapping_config as $idp_id => $domains ) {
			$domains = array_map( 'trim', explode( ';', $domains ) );
			if ( in_array( strtolower( $domain ), array_map( 'strtolower', $domains ), true ) ) {
				$idp_id_to_redirect = $idp_id;
				break;
			}
		}
		if ( ! empty( $idp_id_to_redirect ) || 'default_idp' === $domain_mapping_data->domain_mapping_fail_option ) {
			if ( empty( $idp_id_to_redirect ) ) {
				$default_idp = Utility::get_default_idp();
				if ( ! $default_idp ) {
					if ( ! $ajax ) {
						return wp_json_encode(
							array(
								'success' => false,
								'data'    => 'Default IDP not found',
								'code'    => 404,
							)
						);
					}
					return wp_send_json_error( 'Default IDP not found', 404 );
				}
				$idp_id_to_redirect = $default_idp->idp_id;
			}
			$redirect_url = add_query_arg(
				array(
					'option' => Plugin_Options::SAML_REQUEST_OPTION['SAML_USER_LOGIN'],
					'idp'    => $idp_id_to_redirect,
				),
				site_url( '/' )
			);
			if ( ! $ajax ) {
				return wp_json_encode(
					array(
						'success' => true,
						'data'    => array(
							'status'  => 'redirect',
							'url'     => $redirect_url,
							'message' => 'Redirecting to IDP...',
						),
						'code'    => 200,
					)
				);
			}
			return wp_send_json_success(
				array(
					'status'  => 'redirect',
					'url'     => $redirect_url,
					'message' => 'Redirecting to IDP...',
				)
			);
		} else {
			if ( ! $ajax ) {
				return wp_json_encode(
					array(
						'success' => true,
						'data'    => array(
							'status'  => 'wp_login',
							'url'     => '',
							'message' => 'Login using WordPress credentials',
						),
						'code'    => 200,
					)
				);
			}
			return wp_send_json_success(
				array(
					'status'  => 'wp_login',
					'url'     => '',
					'message' => 'Login using WordPress credentials',
				)
			);
		}
		return parent::fetch_domain_mapping( $user_email );
	}

	/**
	 * Handle domain based redirection.
	 *
	 * @param string $email The user email.
	 * @return void
	 */
	public function handle_domain_based_redirection( $email ) {
		$response = json_decode( self::fetch_domain_mapping( $email, false ) );
		if ( $response->success && 'redirect' === $response->data->status ) {
			wp_safe_redirect( esc_url_raw( $response->data->url ) );
			exit;
		} else {
			echo esc_html( wp_json_encode( $response->data ) );
			exit;
		}
	}

	/**
	 * Get domain mapping IDP.
	 *
	 * @return array
	 */
	public function get_domain_mapping_idp() {
		$domain_mapping_data = $this->get_domain_mapping_data_for_current_environment();

		return $domain_mapping_data->domain_mapping_config;
	}
}
