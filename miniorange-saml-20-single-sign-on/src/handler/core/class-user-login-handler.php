<?php
/**
 * User Login Handler.
 *
 * This class handles the user login process.
 *
 * @package MOSAML\SRC\Handler\Core
 */

namespace MOSAML\SRC\Handler\Core;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\SRC\DTO\SAML_Response_DTO;
use MOSAML\SRC\Utils\Utility;
use Exception;
use MOSAML\SRC\DTO\User_Attributes_DTO;
use MOSAML\SRC\Utils\Error_Success_Message;
use MOSAML\SRC\Constant\Error_Codes_Enums;
use MOSAML\SRC\Exception\Invalid_License_Exception;
use MOSAML\SRC\Utils\Feature_Control;
use MOSAML\SRC\Utils\DB_Utils;
use MOSAML\SRC\Constant\Constants;
use MOSAML\SRC\Exception\Username_Too_Large_Exception;
use MOSAML\SRC\Exception\User_Creation_Failed_Exception;

/**
 * User Login Handler.
 *
 * This class handles the user login process.
 */
class User_Login_Handler {

	/**
	 * Processes a SAML response to authenticate and log in a user to WordPress.
	 * This method validates the SAML response status, extracts user attributes from
	 * assertions, creates or updates the WordPress user account, applies user restrictions,
	 * and performs the actual login with appropriate redirects.
	 *
	 * @param SAML_Response_DTO $saml_response_dto The SAML response DTO.
	 * @return void
	 * @throws Invalid_License_Exception If license is invalid for the current user.
	 * @throws User_Creation_Failed_Exception If user creation fails.
	 */
	public function handle_login( SAML_Response_DTO $saml_response_dto ) {

		$idp_id = $saml_response_dto->get_idp_pk();

		$assertions = $saml_response_dto->get_assertions();
		$assertion  = current( $assertions );

		$name_id         = $assertion->get_name_id();
		$session_index   = $assertion->get_authn_statement_session_index();
		$saml_attributes = array_merge( $assertion->get_attributes(), array( 'NameID' => $name_id ) );
		do_action( 'mosaml_abr_filter_login_internal', $saml_attributes, $name_id, $session_index );
		$saml_attributes['sanitize_further'] = true;

		/**
		 * Filter to modify and sanitize SAML attributes received in the SAML Response.
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
		$saml_attributes = apply_filters( 'mosaml_sanitize_attributes_internal', $saml_attributes );

		$current_environment_id = DB_Utils::get_environment_details( 'id', true );
		// Enterprise fallbacks must use the "All IDPs" aggregate row, not an arbitrary first IdP row from the database.
		$all_idp_id             = DB_Utils::get_default_inserted_idp_details( 'id', $current_environment_id );

		$blog_id_for_environment = Utility::get_subsite_id_for_environment( $current_environment_id );

		$attribute_idp_id = $idp_id;
		$record_exists    = DB_Utils::is_record_exists( Constants::DATABASE_TABLE_NAMES['attribute_mapping'], array( 'idp_id' => $attribute_idp_id ) );
		if ( ! $record_exists && 4 === MOSAML_VERSION && ! empty( $all_idp_id ) ) {
			$attribute_idp_id = $all_idp_id;
		}
		$attribute_data_object = Utility::get_handler_object( 'attribute_mapping_data', true, 'admin' )->get_data( array( 'idp_id' => $attribute_idp_id ) );
		$attributes_handler    = Utility::get_handler_object( 'attribute', true, 'config', $attribute_data_object );
		$user_attributes_dto   = $attributes_handler->get_user_attributes( $saml_attributes );

		if ( ! $user_attributes_dto->get_email() && ! $user_attributes_dto->get_username() ) {
			Error_Success_Message::display_error_code_message( Error_Codes_Enums::$error_codes['WPSAMLERR037'] );
		}

		$attr_role_advanced_settings_recorded = DB_Utils::get_records(
			Constants::DATABASE_TABLE_NAMES['sso_settings'],
			array(
				'option_name' => 'attr_role_advanced_settings_recorded',
				'idp_id'      => $idp_id,
				'subsite_id'  => $blog_id_for_environment,
			),
			true
		);
		$role_assignment_settings_recorded = DB_Utils::get_records(
			Constants::DATABASE_TABLE_NAMES['sso_settings'],
			array(
				'option_name' => 'role_assignment_settings_recorded',
				'idp_id'      => $idp_id,
				'subsite_id'  => $blog_id_for_environment,
			),
			true
		);

		// Advanced options must follow the same IdP row as role mapping when Role Mapping was saved per-IdP (see role block below).
		$attr_role_advanced_settings_idp_id = $idp_id;
		if ( ! $attr_role_advanced_settings_recorded && ! $role_assignment_settings_recorded && 4 === MOSAML_VERSION && ! empty( $all_idp_id ) ) {
			$attr_role_advanced_settings_idp_id = $all_idp_id;
		}

		$attr_role_advanced_settings_data    = Utility::get_handler_object( 'role_mapping_advanced_settings_data', true, 'admin' )->get_data(
			array(
				'idp_id'     => $attr_role_advanced_settings_idp_id,
				'subsite_id' => $blog_id_for_environment,
			)
		);
		$attr_role_advanced_settings_handler = Utility::get_handler_object( 'attr_role_advanced_settings', true, 'config', $attr_role_advanced_settings_data );
		$attr_role_advanced_settings_handler->validate_user_email_domain( $user_attributes_dto->get_email() );
		$attr_role_advanced_settings_handler->validate_user_idp_attribute( $saml_attributes );

		$sanitized_username = sanitize_user( $user_attributes_dto->get_username(), true );

		/**
		 * Filter hook to modify the username before it's used for login or user lookup.
		 *
		 * @param string $username The sanitized username.
		 * @return string The filtered username.
		 */
		$filtered_username = apply_filters( 'mosaml_pre_user_login_internal', $sanitized_username );

		$username = trim( $filtered_username );
		$user_attributes_dto->set_username( $username );

		$user        = Utility::get_user_by_username_or_email( $username, $user_attributes_dto->get_email() );
		$is_new_user = false;

		$role_assignment_settings_idp_id = $idp_id;

		do_action( 'mosaml_update_username_internal', $username, $idp_id );

		if ( ! $role_assignment_settings_recorded && 4 === MOSAML_VERSION && ! empty( $all_idp_id ) ) {
			$role_assignment_settings_idp_id = $all_idp_id;
		}

		$user_roles_data_object           = Utility::get_handler_object( 'role_mapping_data', true, 'admin' )->get_data(
			array(
				'idp_id'     => $role_assignment_settings_idp_id,
				'subsite_id' => $blog_id_for_environment,
			)
		);
		$default_role_mapping_data_object = Utility::get_handler_object( 'role_assignment_settings_data', true, 'admin' )->get_data(
			array(
				'idp_id'     => $role_assignment_settings_idp_id,
				'subsite_id' => $blog_id_for_environment,
			)
		);
		$role_handler                     = Utility::get_handler_object( 'role', true, 'config', $user_roles_data_object, $default_role_mapping_data_object );
		$assigned_roles                   = array();

		if ( ! $user ) {
			if ( 1 !== MOSAML_VERSION && ! Feature_Control::check_is_license_valid() ) {
				throw new Invalid_License_Exception( 'Invalid License' );
			}

			$attr_role_advanced_settings_handler->validate_new_user_creation();
			$assigned_roles = $role_handler->get_assigned_roles( $saml_attributes, $attr_role_advanced_settings_data->enable_regex_for_role_mapping, $idp_id, $user );
			$role_handler->validate_new_user_creation( $assigned_roles );

			$user = $this->create_user( $user_attributes_dto );
			if ( ! $user ) {
				throw new User_Creation_Failed_Exception( 'Failed to get or create user' );
			}
			$is_new_user = true;
		}

		if ( 1 !== MOSAML_VERSION && ! Feature_Control::check_is_license_valid() && ! Utility::mosaml_is_user_administrator( $user ) ) {
			throw new Invalid_License_Exception( 'Invalid License' );
		}

		$attributes_handler->assign_attributes( $user, $user_attributes_dto, $is_new_user );

		$idp_details_array = Utility::convert_idp_details_to_array( $saml_response_dto->get_idp_details() );
		$name_id_value     = $assertion->get_name_id();
		$name_id_array     = is_array( $name_id_value ) ? $name_id_value : array( $name_id_value );
		do_action( 'mosaml_guest_login_internal', $name_id_array, $assertion->get_authn_statement_session_index(), $idp_details_array, $is_new_user );

		if ( $is_new_user || ( 'checked' !== $attr_role_advanced_settings_data->do_not_update_existing_user_roles && ! $is_new_user ) ) {
			if ( ! $assigned_roles ) {
				$assigned_roles = $role_handler->get_assigned_roles( $saml_attributes, $attr_role_advanced_settings_data->enable_regex_for_role_mapping );
			}
			$role_handler->assign_roles( $user, $assigned_roles, $is_new_user, $attr_role_advanced_settings_data->whitelist_existing_users_roles, $attr_role_advanced_settings_data->whitelisted_roles );
		}

		$this->perform_login( $user, $idp_id, $name_id, $session_index );
		$this->mo_saml_trigger_hook_before_redirect( $saml_response_dto->get_relay_state(), $user, $is_new_user, $user_attributes_dto, $saml_attributes, $idp_id );
		$this->redirect_after_login( $saml_response_dto );
	}

	/**
	 * Perform the actual login process
	 *
	 * @param \WP_User $user The WordPress user object.
	 * @param int      $idp_id The IDP ID.
	 * @param string   $name_id The NameID from SAML assertion.
	 * @param string   $session_index The session index from SAML assertion.
	 * @return void
	 */
	private function perform_login( \WP_User $user, $idp_id, $name_id, $session_index ) {
		// Set WordPress user as current user and create auth cookie.
		wp_set_current_user( $user->ID );
		$remember = apply_filters( 'mosaml_remember_me_internal', false );
		$secure   = Utility::mo_saml_is_ssl();
		wp_set_auth_cookie( $user->ID, $remember, $secure );

		// Store SAML session data in user meta for logout and tracking.
		$this->store_saml_user_meta( $user->ID, $idp_id, $name_id, $session_index );

		// Store SAML session data in PHP session for SSO flow.
		$this->store_saml_session_data( $idp_id, $name_id, $session_index );

		// Trigger WordPress login action.
	}

	/**
	 * Trigger SAML hooks before redirect
	 *
	 * @param string              $redirect_url The redirect URL.
	 * @param \WP_User            $user The WordPress user object.
	 * @param bool                $is_new_user Whether this is a new user.
	 * @param User_Attributes_DTO $user_attributes_dto The user attributes DTO.
	 * @param array               $saml_attributes The SAML attributes.
	 * @param string              $idp_id The IDP ID.
	 * @return void
	 */
	private function mo_saml_trigger_hook_before_redirect( $redirect_url, $user, $is_new_user, $user_attributes_dto, $saml_attributes, $idp_id ) {
		if ( ! $redirect_url ) {
			$redirect_url = home_url();
		}

		$blog_id_for_environment = Utility::get_subsite_id_for_environment( DB_Utils::get_environment_details( 'id', true ) );

		// Trigger actions in correct order.
		do_action( 'mosaml_miniorange_post_authenticate_user_login_internal', $user, null, $redirect_url, ! $is_new_user );

		// Get group values for mo_saml_attributes action.
		$user_roles_data_object = Utility::get_handler_object( 'role_assignment_settings_data', true, 'admin' )->get_data(
			array(
				'idp_id'     => $idp_id,
				'subsite_id' => $blog_id_for_environment,
			)
		);
		$idp_details            = Utility::get_handler_object( 'sp_setup_data', true, 'admin' )->get_data( array( 'id' => $idp_id ) );
		$group_attribute_name   = $user_roles_data_object->group_attribute_name;
		$user_idp_group_values  = isset( $saml_attributes[ $group_attribute_name ] ) ? $saml_attributes[ $group_attribute_name ] : array();

		do_action( 'mosaml_attributes_internal', $user_attributes_dto->get_username(), $user_attributes_dto->get_email(), $user_attributes_dto->get_first_name(), $user_attributes_dto->get_last_name(), $user_idp_group_values, $idp_id, $saml_attributes );

		do_action( 'mosaml_wp_user_attributes_internal', $user->ID, $saml_attributes, $idp_details->idp_id, 'SAML', $is_new_user );

		if ( $is_new_user ) {
			do_action( 'mosaml_user_register_internal', $user->ID );
		}

		do_action( 'mosaml_wp_login_internal', $user->user_login, $user );
	}

	/**
	 * Store SAML session data in user meta
	 *
	 * @param int    $user_id The WordPress user ID.
	 * @param int    $idp_id The IDP ID.
	 * @param string $name_id The NameID from SAML assertion.
	 * @param string $session_index The session index from SAML assertion.
	 * @return void
	 */
	private function store_saml_user_meta( $user_id, $idp_id, $name_id, $session_index ) {
		if ( ! empty( $idp_id ) ) {
			update_user_meta( $user_id, 'mo_saml_logged_in_with_idp', $idp_id );
		}

		if ( ! empty( $session_index ) ) {
			update_user_meta( $user_id, 'mo_saml_session_index', $session_index );
		}

		if ( ! empty( $name_id ) ) {
			update_user_meta( $user_id, 'mo_saml_name_id', $name_id );
		}
	}

	/**
	 * Store SAML session data in PHP session
	 *
	 * @param int    $idp_id The IDP ID.
	 * @param string $name_id The NameID from SAML assertion.
	 * @param string $session_index The session index from SAML assertion.
	 * @return void
	 */
	private function store_saml_session_data( $idp_id, $name_id, $session_index ) {
		// Ensure session is started.
		$this->ensure_session_started();

		// Store IDP ID in session.
		$_SESSION['mo_saml']['logged_in_with_idp'] = $idp_id;

		if ( ! empty( $session_index ) ) {
			$_SESSION['mo_saml']['sessionIndex'] = $session_index;
		}

		if ( ! empty( $name_id ) ) {
			$_SESSION['mo_saml']['nameId'] = $name_id;
		}
	}

	/**
	 * Ensure PHP session is started
	 *
	 * @return void
	 */
	private function ensure_session_started() {
		if ( session_status() === PHP_SESSION_NONE ) {
			session_start();
		}
	}

	/**
	 * Redirect after login
	 *
	 * @param SAML_Response_DTO $saml_response_dto The SAML response DTO.
	 * @return void
	 */
	private function redirect_after_login( SAML_Response_DTO $saml_response_dto ) {
		$redirect_url = null;
		$idp_id       = $saml_response_dto->get_idp_details() && isset( $saml_response_dto->get_idp_details()->id ) ? $saml_response_dto->get_idp_details()->id : null;

		$relay_state_handler = Utility::get_handler_object( 'relay_state_data', true, 'admin' );

		// First, check for relay state for the specific IDP.
		if ( ! is_null( $idp_id ) ) {
			$relay_state_data = $relay_state_handler->get_data( array( 'idp_id' => $idp_id ) );

			if ( ! empty( $relay_state_data->login_relay_state ) ) {
				$redirect_url = $relay_state_data->login_relay_state;
			}
		}

		// If not set for specific IDP, check for "All IDPs" relay state.
		if ( empty( $redirect_url ) ) {
			$all_idps_idp = Utility::get_all_idps_idp();
			if ( ! is_null( $all_idps_idp ) && isset( $all_idps_idp->id ) ) {
				$all_idps_relay_state_data = $relay_state_handler->get_data( array( 'idp_id' => $all_idps_idp->id ) );

				if ( ! empty( $all_idps_relay_state_data->login_relay_state ) ) {
					$redirect_url = $all_idps_relay_state_data->login_relay_state;
				}
			}
		}

		// If still not set, use relay state from SAML response DTO.
		if ( empty( $redirect_url ) ) {
			$redirect_url = $saml_response_dto->get_relay_state();
		}

		// If still empty, redirect to home URL.
		if ( ! $redirect_url ) {
			$redirect_url = home_url();
		}

		$redirect_url = apply_filters( 'mosaml_login_redirect_url_internal', $redirect_url );
		/**
		 * Filter to change the relay state after the SAML Login Response.
		 *
		 * @since 25.2.7
		 *
		 * @param string  $redirect_url
		 */
		$redirect_url = apply_filters( 'mosaml_post_login_sso_relay_state_internal', $redirect_url );
		wp_safe_redirect( $redirect_url );
		exit;
	}

	/**
	 * Create a new WordPress user based on SAML attributes
	 *
	 * @param User_Attributes_DTO $user_attributes_dto The user attributes DTO.
	 * @return \WP_User|null The WordPress user object or null if creation fails
	 * @throws Username_Too_Large_Exception If username is too large.
	 * @throws User_Creation_Failed_Exception If user creation fails.
	 */
	private function create_user( User_Attributes_DTO $user_attributes_dto ) {
		$email    = $user_attributes_dto->get_email();
		$username = $user_attributes_dto->get_username();

		// Username should already be filtered via pre_user_login in handle_login, but ensure it's sanitized here too.
		$username = sanitize_user( $username, true );
		/**
		 * Filter hook to modify the username before user creation.
		 *
		 * @param string $username The sanitized username.
		 * @return string The filtered username.
		 */
		$username = trim( apply_filters( 'mosaml_pre_user_login_internal', $username ) );

		if ( strlen( $username ) > 60 ) {
			throw new Username_Too_Large_Exception( 'Username is too large' );
		}

		$password = wp_generate_password();

		$user_id = wp_create_user( $username, $password, $email );
		if ( is_wp_error( $user_id ) ) {
			throw new User_Creation_Failed_Exception( esc_html( $user_id->get_error_message() ) );
		}

		return get_user_by( 'id', $user_id );
	}
}
