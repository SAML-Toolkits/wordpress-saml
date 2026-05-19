<?php
/**
 * Login page auto redirection handler (standard module).
 *
 * @package miniorange-saml-20-single-sign-on
 */

namespace MOSAML\Module\Standard\Handler\Core;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\Module\Base\Handler\Core\Login_Page_Auto_Redirection_Handler as Base_Login_Page_Auto_Redirection_Handler;
use MOSAML\SRC\Utils\DB_Utils;
use MOSAML\SRC\Utils\Utility;
use MOSAML\SRC\Constant\Plugin_Options;
use MOSAML\SRC\Utils\Error_Success_Message;
use MOSAML\SRC\Constant\Error_Codes_Enums;

/**
 * Login Page Auto Redirection Handler.
 */
class Login_Page_Auto_Redirection_Handler extends Base_Login_Page_Auto_Redirection_Handler {

	/**
	 * Handle login page auto redirection.
	 *
	 * @return void
	 */
	public function handle_login_page_auto_redirection() {
		$redirect_to = Utility::sanitize_request_data( 'redirect_to' );
		$redirect_to = is_array( $redirect_to ) ? reset( $redirect_to ) : $redirect_to;

		if ( empty( $redirect_to ) ) {
			$redirect_to = home_url();
		}

		if ( Utility::mo_saml_is_user_logged_in() ) {
			wp_safe_redirect( $redirect_to );
			exit();
		}

		/**
		 * Filter hook to prevent auto-redirection before it happens.
		 *
		 * @param bool $prevent_redirect Whether to prevent the auto-redirection. Default false.
		 * @return bool True to prevent auto-redirection, false to allow it.
		 */
		$prevent_redirect = apply_filters( 'mosaml_before_auto_redirect_internal', false );
		if ( $prevent_redirect ) {
			return;
		}
		$auto_redirection_disabled = apply_filters( 'mosaml_pre_auto_redirection_internal', false );
		if ( $auto_redirection_disabled ) {
			return;
		}
		$where = array(
			'option_name' => 'redirect_from_wp_login',
			'subsite_id'  => Utility::get_subsite_id_for_environment( DB_Utils::get_environment_details( 'id', true ) ),
			'idp_id'      => DB_Utils::get_default_inserted_idp_details( 'id', DB_Utils::get_environment_details( 'id' ) ),
		);
		if ( Utility::is_legacy_data_fallback_required() ) {
			$self_object = apply_filters( 'mosaml_legacy_data_fallback_object', $this, $where );

			$this->redirect_from_wp_login = $self_object->redirect_from_wp_login;
		} else {
			$record = DB_Utils::get_records(
				$this->get_table_name(),
				$where,
				true
			);
			if ( $record ) {
				$this->redirect_from_wp_login = $record->option_value;
			}
		}
		if ( 'checked' !== $this->redirect_from_wp_login ) {
			return;
		}

		$where = array(
			'option_name' => 'enable_backdoor_url_login',
			'subsite_id'  => Utility::get_subsite_id_for_environment( DB_Utils::get_environment_details( 'id', true ) ),
			'idp_id'      => DB_Utils::get_default_inserted_idp_details( 'id', DB_Utils::get_environment_details( 'id' ) ),
		);
		if ( Utility::is_legacy_data_fallback_required() ) {
			$self_object                     = apply_filters( 'mosaml_legacy_data_fallback_object', $this, $where );
			$this->enable_backdoor_url_login = $self_object->enable_backdoor_url_login;
		} else {
			$record = DB_Utils::get_records(
				$this->get_table_name(),
				$where,
				true
			);
			if ( $record ) {
				$this->enable_backdoor_url_login = $record->option_value;
			}
		}
		if ( 'checked' === $this->enable_backdoor_url_login ) {
			$where = array(
				'option_name' => 'backdoor_url',
				'subsite_id'  => Utility::get_subsite_id_for_environment( DB_Utils::get_environment_details( 'id', true ) ),
				'idp_id'      => DB_Utils::get_default_inserted_idp_details( 'id', DB_Utils::get_environment_details( 'id' ) ),
			);
			if ( Utility::is_legacy_data_fallback_required() ) {
				$self_object        = apply_filters( 'mosaml_legacy_data_fallback_object', $this, $where );
				$this->backdoor_url = $self_object->backdoor_url;
			} else {
				$record = DB_Utils::get_records(
					$this->get_table_name(),
					$where,
					true
				);
				if ( $record ) {
					$this->backdoor_url = $record->option_value;
				}
			}

			if ( ! empty( $this->backdoor_url ) && Utility::sanitize_request_data( 'saml_sso' ) === $this->backdoor_url ) {
				return;
			}

			if ( ! empty( $redirect_to ) && strpos( $redirect_to, 'wp-admin' ) !== false && strpos( $redirect_to, 'saml_sso=' . $this->backdoor_url ) !== false ) {
				return;
			}
		}

		if ( Utility::is_legacy_data_fallback_required() ) {
			$default_idp = apply_filters(
				'mosaml_legacy_data_fallback_object',
				Utility::get_handler_object( 'sp_setup_data', true, 'admin' ),
				array(
					'environment_id' => DB_Utils::get_environment_details( 'id' ),
					'default_idp'    => true,
					'status'         => 'active',
				)
			);
		} else {
			$default_idp = Utility::get_default_idp();
		}
		if ( ! $default_idp ) {
			Error_Success_Message::display_error_code_message( Error_Codes_Enums::$error_codes['WPSAMLERR034'] );
		}

		$idp_id       = $default_idp->idp_id;
		$redirect_url = add_query_arg(
			array(
				'option'      => Plugin_Options::SAML_REQUEST_OPTION['SAML_USER_LOGIN'],
				'idp'         => $idp_id,
				'redirect_to' => $redirect_to,
			),
			site_url( '/' )
		);
		wp_safe_redirect( $redirect_url );
		exit;
	}
}
