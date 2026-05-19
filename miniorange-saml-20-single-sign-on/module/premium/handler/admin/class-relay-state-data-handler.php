<?php
/**
 * Premium Relay State Data Handler.
 *
 * @package miniorange-saml-20-single-sign-on/module/premium/handler/admin
 */

namespace MOSAML\Module\Premium\Handler\Admin;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\Module\Standard\Handler\Admin\Relay_State_Data_Handler as Standard_Relay_State_Data_Handler;
use MOSAML\SRC\Interfaces\Form_Data_Handler_Interface;
use MOSAML\SRC\Utils\DB_Utils;
use MOSAML\SRC\Utils\Error_Success_Message;
use MOSAML\SRC\Utils\Utility;


/**
 * Premium Relay State Data Handler.
 */
class Relay_State_Data_Handler extends Standard_Relay_State_Data_Handler implements Form_Data_Handler_Interface {

	/**
	 * Validate and save the data.
	 *
	 * @return void
	 */
	public function validate_and_save_data() {
		$idp_id = Utility::sanitize_post_data( 'mo_saml_relay_state_idp_name' );
		if ( empty( $idp_id ) || 'DEFAULT' === $idp_id ) {
			$idp_id = DB_Utils::get_default_inserted_idp_details( 'id', false );
		}

		if ( is_null( $idp_id ) ) {
			return;
		}

		$this->allow_third_party_relay_state = Utility::sanitize_post_data( 'mo_saml_allow_3rd_party_url' );
		$this->login_relay_state             = Utility::sanitize_post_data( 'mo_saml_login_relay_state' );
		$this->logout_relay_state            = Utility::sanitize_post_data( 'mo_saml_logout_relay_state' );

		if ( empty( $this->allow_third_party_relay_state ) && ( Utility::is_3rd_party_url( $this->login_relay_state ) || Utility::is_3rd_party_url( $this->logout_relay_state ) ) ) {
			Error_Success_Message::show_admin_notice( '3rd party URL detected. Please enter URL of the current site.' );
			return;
		}
		if ( ! is_null( $this->login_relay_state ) && ! empty( $this->login_relay_state ) && filter_var( $this->login_relay_state, FILTER_VALIDATE_URL ) === false ) {
			Error_Success_Message::show_admin_notice( 'Please enter a valid Login Relay State URL.' );
			return;
		}
		if ( ! is_null( $this->logout_relay_state ) && ! empty( $this->logout_relay_state ) && filter_var( $this->logout_relay_state, FILTER_VALIDATE_URL ) === false ) {
			Error_Success_Message::show_admin_notice( 'Please enter a valid Logout Relay State URL.' );
			return;
		}

		$this->insert_or_update_setting( 'allow_third_party_relay_state', $this->allow_third_party_relay_state, $idp_id );
		$this->insert_or_update_setting( 'login_relay_state', $this->login_relay_state, $idp_id );
		$this->insert_or_update_setting( 'logout_relay_state', $this->logout_relay_state, $idp_id );
	}

	/**
	 * Get the data.
	 *
	 * @param array $where The where clause to filter the data.
	 * @return object The data.
	 */
	public function get_data( $where = array() ) {
		parent::get_data( $where );

		$idp_id = isset( $where['idp_id'] ) ? $where['idp_id'] : null;

		if ( is_null( $idp_id ) ) {
			$idp_id = Utility::sanitize_request_data( 'idp_id', false, 'DEFAULT' );
		}

		if ( 'DEFAULT' === $idp_id || empty( $idp_id ) ) {
			$idp_id = DB_Utils::get_default_inserted_idp_details( 'id', false );
		}

		if ( is_null( $idp_id ) ) {
			return $this;
		}

		$logout = $this->get_setting_value( 'logout_relay_state', $idp_id );
		if ( ! is_null( $logout ) ) {
			$this->logout_relay_state = $logout;
		}

		$allow_third_party = $this->get_setting_value( 'allow_third_party_relay_state', $idp_id );
		if ( ! is_null( $allow_third_party ) ) {
			$this->allow_third_party_relay_state = $allow_third_party;
		} else {
			$this->allow_third_party_relay_state = 'checked';
		}

		return $this;
	}
}
