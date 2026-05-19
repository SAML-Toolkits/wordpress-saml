<?php
/**
 * Shortcode Data Handler - Standard Module
 *
 * Extends the base shortcode data handler to provide standard module functionality.
 *
 * PHP Compatibility: 5.6+
 *
 * @package miniorange-saml-20-single-sign-on
 * @subpackage Module\Standard\Handler\Admin
 */

namespace MOSAML\Module\Standard\Handler\Admin;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\Module\Base\Handler\Admin\Shortcode_Data_Handler as Base_Shortcode_Data_Handler;
use MOSAML\SRC\Interfaces\Form_Data_Handler_Interface;
use MOSAML\SRC\Utils\DB_Utils;
use MOSAML\SRC\Utils\Utility;
use MOSAML\SRC\Handler\UI\Login_Page_UI_Handler;
use MOSAML\SRC\Utils\Feature_Control;

/**
 * Shortcode Data Handler.
 */
class Shortcode_Data_Handler extends Base_Shortcode_Data_Handler implements Form_Data_Handler_Interface {

	/**
	 * Render SSO login link for [MO_SAML_FORM idp="..."]
	 *
	 * @param array $atts Shortcode attributes.
	 * @return string HTML output.
	 */
	public function render_form_shortcode( $atts ) {
		if ( ! Feature_Control::check_is_license_verified() ) {
			return;
		}

		if ( is_user_logged_in() ) {
			$current_user = wp_get_current_user();

			$idp_details = Utility::get_handler_object( 'sp_setup_data', true, 'admin' )->get_data(
				array(
					'idp_id' => $atts['idp'],
				)
			);
			if ( ! empty( $idp_details ) ) {
				$logged_in_idp_id = $idp_details->id;
			} else {
				$logged_in_idp_id = get_user_meta( $current_user->ID, 'mo_saml_logged_in_with_idp', true );
			}

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

		$shortcode_attributes = is_array( $atts ) ? $atts : array();
		$default_idp_id       = Utility::get_default_idp() ? Utility::get_default_idp()->idp_id : '';
		$idp_id               = isset( $shortcode_attributes['idp'] ) ? sanitize_text_field( $shortcode_attributes['idp'] ) : $default_idp_id;
		$environment_id       = DB_Utils::get_environment_details( 'id' );
		$idp_record           = Utility::get_idp_details_from_idp_id( $idp_id, $environment_id );

		if ( is_null( $idp_record ) || empty( $idp_record->idp_name ) ) {
			return '<div class="mosaml-shortcode-error">IDP not found.</div>';
		}

		$redirect_to_url = rawurlencode( Utility::get_current_page_url() );
		$sso_login_url   = home_url() . '/?option=saml_user_login&idp=' . rawurlencode( $idp_record->idp_id ) . '&redirect_to=' . $redirect_to_url;

		$login_text       = '';
		$idp_display_name = ( $idp_record && isset( $idp_record->idp_name ) ) ? $idp_record->idp_name : $idp_record->idp_id;

		if ( $idp_record && isset( $idp_record->id ) ) {
			$shortcode_widget_handler = Utility::get_handler_object( 'shortcode_widget_data', true, 'admin' );
			$shortcode_widget_data    = $shortcode_widget_handler->get_data(
				array(
					'subsite_id' => Utility::get_subsite_id_for_environment(),
					'idp_id'     => $idp_record->id, // Use the integer ID, not the string idp_id.
				)
			);

			if ( ! empty( $shortcode_widget_data->widget_config['custom_login_text'] ) ) {
				$login_text = $shortcode_widget_data->widget_config['custom_login_text'];
			}
		}

		if ( '' === $login_text ) {
			$login_text = 'Login with ' . $idp_display_name;
		}

		if ( $idp_record && isset( $idp_record->id ) ) {
			$sso_button_handler = Utility::get_handler_object( 'sso_button_data', true, 'admin' );
			$sso_button_data    = $sso_button_handler->get_data(
				array(
					'idp_id'     => $idp_record->id,
					'subsite_id' => Utility::get_subsite_id_for_environment(),
				)
			);

			$use_button_as_shortcode = ! empty( $sso_button_data->use_button_as_shortcode ) ? $sso_button_data->use_button_as_shortcode : ( ! empty( $sso_button_data->sso_button_config['use_button_as_shortcode'] ) ? $sso_button_data->sso_button_config['use_button_as_shortcode'] : '' );
			if ( ! empty( $use_button_as_shortcode ) && 'checked' === $use_button_as_shortcode ) {
				if ( empty( $sso_button_data->sso_button_config['button_text'] ) ) {
					$sso_button_data->sso_button_config['button_text'] = $login_text;
				}
				return Login_Page_UI_Handler::generate_sso_button_html( $sso_button_data, $idp_record->id, $sso_login_url );
			}
		}

		return '<a style="text-decoration : none;" href="' . esc_url( $sso_login_url ) . '">' . esc_html( $login_text ) . '</a>';
	}
}
