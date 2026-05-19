<?php
/**
 * Shortcode Data Handler - Enterprise Module
 *
 * Extends the premium shortcode data handler to provide enterprise module functionality.
 *
 * PHP Compatibility: 5.6+
 *
 * @package miniorange-saml-20-single-sign-on
 */

namespace MOSAML\Module\Enterprise\Handler\Admin;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\Module\Premium\Handler\Admin\Shortcode_Data_Handler as Premium_Shortcode_Data_Handler;
use MOSAML\SRC\Constant\Constants;
use MOSAML\SRC\Interfaces\Form_Data_Handler_Interface;
use MOSAML\SRC\Utils\DB_Utils;
use MOSAML\SRC\Utils\Error_Success_Message;
use MOSAML\SRC\Utils\Utility;
use MOSAML\SRC\Utils\Feature_Control;

/**
 * Shortcode Data Handler.
 */
class Shortcode_Data_Handler extends Premium_Shortcode_Data_Handler implements Form_Data_Handler_Interface {

	/**
	 * Validate and save the shortcode configuration.
	 *
	 * @return void
	 */
	public function validate_and_save_data() {
		$this->shortcode_login_text = Utility::sanitize_post_data( 'mo_saml_shortcode_login_text' );
		$idp_id                     = DB_Utils::get_default_inserted_idp_details( 'id', DB_Utils::get_environment_details( 'id', false ) );
		$table_data                 = array(
			'option_name'  => 'shortcode_login_text',
			'option_value' => $this->shortcode_login_text,
			'idp_id'       => $idp_id,
			'subsite_id'   => Utility::get_subsite_id_for_environment(),
		);
		$query_result               = DB_Utils::insert_or_update(
			$this->get_table_name(),
			$table_data,
			array(
				'option_name' => 'shortcode_login_text',
				'idp_id'      => $idp_id,
				'subsite_id'  => Utility::get_subsite_id_for_environment(),
			)
		);
		if ( $query_result ) {
			Error_Success_Message::show_admin_notice( 'Shortcode Login text updated successfully.', 'SUCCESS' );
		}
	}

	/**
	 * Render IDP list for [MO_SAML_IDP_LIST].
	 *
	 * @return string HTML output.
	 */
	public function render_idp_list_shortcode() {
		if ( 4 !== MOSAML_VERSION || ! Feature_Control::check_is_license_verified() ) {
			return;
		}

		if ( is_user_logged_in() ) {
			$current_user = wp_get_current_user();

			$logged_in_idp_id = get_user_meta( $current_user->ID, 'mo_saml_logged_in_with_idp', true );

			$shortcode_widget_handler = Utility::get_handler_object( 'shortcode_widget_data', true, 'admin' );
			$shortcode_widget_data    = $shortcode_widget_handler->get_data(
				array(
					'subsite_id' => Utility::get_subsite_id_for_environment(),
					'idp_id'     => $logged_in_idp_id,
				)
			);

			$greeting_text   = ! empty( $shortcode_widget_data->widget_config['custom_greeting_text'] ) ? $shortcode_widget_data->widget_config['custom_greeting_text'] : 'Hello,';
			$logout_text     = ! empty( $shortcode_widget_data->widget_config['custom_logout_text'] ) ? $shortcode_widget_data->widget_config['custom_logout_text'] : 'Logout';
			$greeting_option = isset( $shortcode_widget_data->widget_config['greeting_name'] ) ? $shortcode_widget_data->widget_config['greeting_name'] : 'USERNAME';

			$username = Utility::get_user_name( $current_user, $greeting_option );

			$logout_url = wp_logout_url( Utility::get_current_page_url() );
			return esc_html( $greeting_text . ' ' . $username ) . ' | <a href="' . esc_url( $logout_url ) . '" title="logout">' . esc_html( $logout_text ) . '</a>';
		}

		$environment_id = DB_Utils::get_environment_details( 'id' );
		$idp_records    = DB_Utils::get_records( Constants::DATABASE_TABLE_NAMES['idp_details'], array( 'environment_id' => $environment_id ), false );
		if ( empty( $idp_records ) || ! is_array( $idp_records ) ) {
			return '<div class="mosaml-shortcode-error">No IDPs configured.</div>';
		}

		$login_text_data = DB_Utils::get_records(
			Constants::DATABASE_TABLE_NAMES['sso_settings'],
			array(
				'option_name' => 'shortcode_login_text',
				'idp_id'      => DB_Utils::get_default_inserted_idp_details( 'id', $environment_id ),
			),
			true
		);

		$login_text = 'Login with';
		if ( $login_text_data ) {
			$login_text = $login_text_data->option_value;
		}

		$redirect_to_url = rawurlencode( Utility::get_current_page_url() );

		$html_output  = $login_text . '  ';
		$html_output .= '<select onchange="redirectToIDP(this.value)"><option disabled selected>--Select your IDP--</option>';
		foreach ( $idp_records as $idp_record ) {
			if ( isset( $idp_record->status ) && 'inactive' === $idp_record->status ) {
				continue;
			}
			$idp_label      = isset( $idp_record->idp_name ) ? $idp_record->idp_name : ( isset( $idp_record->entity_id ) ? $idp_record->entity_id : 'IDP' );
			$idp_identifier = isset( $idp_record->idp_id ) ? $idp_record->idp_id : '';
			if ( empty( $idp_identifier ) ) {
				continue;
			}
			$sso_login_url = home_url() . '/?option=saml_user_login&idp=' . rawurlencode( $idp_identifier ) . '&redirect_to=' . $redirect_to_url;
			$html_output  .= '<option value="' . esc_url( $sso_login_url ) . '">' . esc_html( $idp_label ) . '</option>';
		}
		$html_output .= '</select><script>function redirectToIDP(url){location=url;}</script>';
		return $html_output;
	}
}
