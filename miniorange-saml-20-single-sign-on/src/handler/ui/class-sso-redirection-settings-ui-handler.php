<?php
/**
 * SSO Redirection Settings UI Handler.
 *
 * @package miniorange-saml-20-single-sign-on
 */

namespace MOSAML\SRC\Handler\UI;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\SRC\Interfaces\Tab_UI_Handler_Interface;
use MOSAML\SRC\Utils\Utility;
use MOSAML\SRC\Utils\DB_Utils;
use MOSAML\SRC\Constant\Constants;
use MOSAML\SRC\Constant\Plugin_Files_Constants;
use MOSAML\SRC\Utils\Feature_Control;

/**
 * SSO Redirection Settings Handler.
 */
class SSO_Redirection_Settings_UI_Handler implements Tab_UI_Handler_Interface {
	/**
	 * Render the UI.
	 *
	 * @return void
	 */
	public function render_ui() {
		$active_tab = Utility::sanitize_get_data( 'subtab' );

		if ( empty( $active_tab ) ) {
			$active_tab = '';
		}

		if ( 'sso_links' !== $active_tab ) {
			$active_tab = 'settings';
		}

		require_once Plugin_Files_Constants::TEMPLATE_SSO_REDIRECTION_MAIN;

		if ( 'sso_links' === $active_tab ) {
			$this->render_sso_links_ui();
		} else {
			$this->render_sso_redirection_settings_ui();
		}
	}

	/**
	 * Render the SSO links UI.
	 *
	 * @return void
	 */
	public function render_sso_links_ui() {
		$disabled                = Utility::disable_forms_if_no_idps_configured_bool();
		$disable_due_to_no_idp   = Utility::disable_forms_if_no_idps_configured();
		$disabled_due_to_license = Utility::mo_saml_get_disabled_attribute( ! Feature_Control::free_or_license_specific_feature_enabled() );

		$sp_base_url = DB_Utils::get_sp_details( 'sp_base_url', false );
		$login_url   = $sp_base_url . '/wp-login.php';
		$admin_url   = $sp_base_url . '/wp-admin/';

		$configured_idps_id = DB_Utils::get_configured_idps_details( 'idp_id', false, true );
		$identity_providers = DB_Utils::get_configured_idps_details( '', false, true );
		$is_enterprise      = 4 === MOSAML_VERSION;

		$environment_id = DB_Utils::get_environment_details( 'id', false );
		$idp_id         = Utility::get_selected_idp_id_from_url( $is_enterprise, $configured_idps_id, 'sso_link_idp' );
		$selected_idp   = DB_Utils::get_records(
			Constants::DATABASE_TABLE_NAMES['idp_details'],
			array(
				'idp_id'         => $idp_id,
				'environment_id' => $environment_id,
			),
			true
		);
		$subsite_id = Utility::get_subsite_id_for_environment( $environment_id );
		$id       = ! empty( $selected_idp ) ? $selected_idp->id : '';
		$idp_name = ! empty( $selected_idp ) ? $selected_idp->idp_name : '';

		$hide_wp_login_handler    = Utility::get_handler_object( 'hide_wp_login_data', true, 'admin' );
		$default_idp_id           = DB_Utils::get_default_inserted_idp_details( 'id', DB_Utils::get_environment_details( 'id', false ) );
		$hide_wp_login_value      = $hide_wp_login_handler->get_data(
			array(
				'idp_id'     => $default_idp_id,
				'subsite_id' => $subsite_id,
			)
		);
		$shortcode_handler        = Utility::get_handler_object( 'shortcode_data', true, 'admin' );
		$shortcode_value          = $shortcode_handler->get_data(
			array(
				'option_name' => 'shortcode_login_text',
				'idp_id'      => $default_idp_id,
			)
		);
		$shortcode_widget_handler = Utility::get_handler_object( 'shortcode_widget_data', true, 'admin' );
		$shortcode_widget_value   = $shortcode_widget_handler->get_data(
			array(
				'option_name' => 'widget_config',
				'idp_id'      => $id,
			)
		);
		$sso_button_handler       = Utility::get_handler_object( 'sso_button_data', true, 'admin' );
		$sso_button_value         = $sso_button_handler->get_data(
			array(
				'idp_id' => $id,
			)
		);
		$button_theme             = ! empty( $sso_button_value->sso_button_config['button_type'] ) ? $sso_button_value->sso_button_config['button_type'] : 'longbutton';
		$button_size              = ! empty( $sso_button_value->sso_button_config['button_size'] ) ? $sso_button_value->sso_button_config['button_size'] : '50';
		$button_width             = ! empty( $sso_button_value->sso_button_config['button_width'] ) ? $sso_button_value->sso_button_config['button_width'] : '270';
		$button_height            = ! empty( $sso_button_value->sso_button_config['button_height'] ) ? $sso_button_value->sso_button_config['button_height'] : '30';
		$button_curve             = ! empty( $sso_button_value->sso_button_config['button_curve'] ) ? $sso_button_value->sso_button_config['button_curve'] : '3';
		$button_text              = ! empty( $sso_button_value->sso_button_config['button_text'] ) ? $sso_button_value->sso_button_config['button_text'] : 'Login with ' . ( isset( $selected_idp->idp_name ) ? $selected_idp->idp_name : '' );
		$button_color             = ! empty( $sso_button_value->sso_button_config['button_color'] ) ? $sso_button_value->sso_button_config['button_color'] : '#2271b1';
		$font_size                = ! empty( $sso_button_value->sso_button_config['font_size'] ) ? $sso_button_value->sso_button_config['font_size'] : '14';
		$font_color               = ! empty( $sso_button_value->sso_button_config['font_color'] ) ? $sso_button_value->sso_button_config['font_color'] : '#ffffff';
		$sso_button_position      = ! empty( $sso_button_value->sso_button_config['button_position'] ) ? $sso_button_value->sso_button_config['button_position'] : 'above';
		$add_button_wp            = ! empty( $sso_button_value->enable_sso_button ) ? $sso_button_value->enable_sso_button : '';
		$use_button_as_shortcode  = ! empty( $sso_button_value->sso_button_config['use_button_as_shortcode'] ) ? $sso_button_value->sso_button_config['use_button_as_shortcode'] : ( ! empty( $sso_button_value->use_button_as_shortcode ) ? $sso_button_value->use_button_as_shortcode : '' );
		$use_button_as_widget     = ! empty( $sso_button_value->sso_button_config['use_button_as_widget'] ) ? $sso_button_value->sso_button_config['use_button_as_widget'] : ( ! empty( $sso_button_value->use_button_as_widget ) ? $sso_button_value->use_button_as_widget : '' );

		require_once Plugin_Files_Constants::TEMPLATE_SSO_LINKS_AND_BUTTONS;
	}

	/**
	 * Render the SSO redirection settings UI.
	 *
	 * @return void
	 */
	public function render_sso_redirection_settings_ui() {
		$disabled                = Utility::disable_forms_if_no_idps_configured_bool();
		$disable_due_to_no_idp   = Utility::disable_forms_if_no_idps_configured();
		$disabled_due_to_license = Utility::mo_saml_get_disabled_attribute( ! Feature_Control::free_or_license_specific_feature_enabled() );

		$sp_base_url = DB_Utils::get_sp_details( 'sp_base_url', false );
		$login_url   = $sp_base_url . '/wp-login.php';
		$admin_url   = $sp_base_url . '/wp-admin/';

		$configured_idps_id = DB_Utils::get_configured_idps_details( 'idp_id', false, false );
		$identity_providers = DB_Utils::get_configured_idps_details( '', false, false );
		$is_enterprise      = 4 === MOSAML_VERSION;
		$idp_id             = Utility::get_selected_idp_id_from_url( $is_enterprise, $configured_idps_id );

		$environment_id           = DB_Utils::get_environment_details( 'id', false );
		$selected_environment_url = DB_Utils::get_environment_details( 'environment_url', false );

		$disable_site_auto_redirect_toggle   = $disable_due_to_no_idp;
		$disable_login_page_redirect_toggle  = $disable_due_to_no_idp;
		$disable_force_authentication_toggle = $disable_due_to_no_idp;
		$disable_rss_feed_access_toggle      = $disable_due_to_no_idp;

		$selected_idp = array_filter(
			$identity_providers,
			function ( $idp ) use ( $idp_id ) {
				if ( $idp->idp_id === $idp_id ) {
					return $idp;
				}
			}
		);

		$selected_idp = reset( $selected_idp );
		$subsite_id = Utility::get_subsite_id_for_environment( $environment_id );
		$id                      = ! empty( $selected_idp ) ? $selected_idp->id : 'All IDPs';
		$selected_env_all_idp_id = DB_Utils::get_default_inserted_idp_details( 'id', $environment_id );
		$selected_env_where      = array(
			'idp_id'     => $selected_env_all_idp_id,
			'subsite_id' => $subsite_id,
		);
		$force_auth_handler           = Utility::get_handler_object( 'force_authentication_data', true, 'admin' );
		$force_auth_data              = $force_auth_handler->get_data( $selected_env_where );
		$force_authentication_enabled = $force_auth_data->enable_force_authentication ? true : false;
		if ( $force_authentication_enabled && Utility::handle_license_calls( 'is_license_valid', 'library', false ) ) {
			$disable_force_authentication_toggle = '';
		}

		$rss_feed_access_data_handler = Utility::get_handler_object( 'rss_feed_access_data', true, 'admin' );
		$rss_feed_access_data         = $rss_feed_access_data_handler->get_data( $selected_env_where );
		if ( 'checked' === $rss_feed_access_data->enable_rss_feed_access && Utility::handle_license_calls( 'is_license_valid', 'library', false ) ) {
			$disable_rss_feed_access_toggle = '';
		}

		$backdoor_url_login_data_handler = Utility::get_handler_object( 'backdoor_url_login_data', true, 'admin' );
		$backdoor_url_login_data         = $backdoor_url_login_data_handler->get_data( $selected_env_where );
		$disable_backdoor_url_options    = 'checked' !== $backdoor_url_login_data->enable_backdoor_url_login ? 'disabled' : '';

		$backdoor_login_url_data = Utility::get_handler_object( 'backdoor_url_login_data', true, 'admin' );
		$backdoor_login_url_data->get_data( $selected_env_where );

		$configured_idps                 = DB_Utils::get_records( Constants::DATABASE_TABLE_NAMES['idp_details'], array( 'environment_id' => $environment_id ) );
		$configured_idps                 = is_array( $configured_idps ) ? $configured_idps : array();
		$configured_idps_without_default = array_filter(
			$configured_idps,
			function ( $idp ) {
				return 'All IDPs' !== $idp->idp_name;
			}
		);
		usort(
			$configured_idps_without_default,
			function ( $a, $b ) {
				$result = (int) $b->default_idp - (int) $a->default_idp;
				if ( 0 !== $result ) {
					return $result;
				}
				return 0;
			}
		);

		$domain_mapping_data_handler = Utility::get_handler_object( 'domain_mapping_data', true, 'admin' );
		$domain_mapping_data         = $domain_mapping_data_handler->get_data( $selected_env_where );

		$disable_domain_mapping         = '';
		$disable_domain_mapping_options = 'checked' !== $domain_mapping_data->enable_domain_mapping ? 'disabled' : '';

		$login_page_auto_redirection_data_handler = Utility::get_handler_object( 'login_page_auto_redirection_data', true, 'admin' );
		$login_page_auto_redirection_data         = $login_page_auto_redirection_data_handler->get_data( $selected_env_where );

		if ( 'checked' === $login_page_auto_redirection_data->redirect_from_wp_login && Utility::handle_license_calls( 'is_license_valid', 'library', false ) ) {
			$disable_login_page_redirect_toggle = '';
		}

		$relay_state_data = Utility::get_handler_object( 'relay_state_data', true, 'admin' );
		$relay_state_data->get_data( array( 'idp_id' => $id ) );

		$site_auto_redirection_data_handler = Utility::get_handler_object( 'site_auto_redirection_data', true, 'admin' );
		$site_auto_redirection_data         = $site_auto_redirection_data_handler->get_data( $selected_env_where );
		if ( ! $site_auto_redirection_data->public_page_url ) {
			$site_auto_redirection_data->public_page_url = $sp_base_url;
		}
		$disable_site_auto_redirect_options = 'checked' !== $site_auto_redirection_data->enable_site_auto_redirect ? 'disabled' : '';
		$disable_public_page_url_options    = 'checked' !== $site_auto_redirection_data->enable_site_auto_redirect || 'public_page' !== $site_auto_redirection_data->site_auto_redirection_option ? 'disabled' : '';
		$current_environment_id             = DB_Utils::get_environment_details( 'id', true );
		$wp_login_url                       = $environment_id === $current_environment_id ? wp_login_url() : $selected_environment_url . '/wp-login.php';
		$wp_admin_url                       = $environment_id === $current_environment_id ? admin_url() : $selected_environment_url . '/wp-admin/';

		if ( 'checked' === $site_auto_redirection_data->enable_site_auto_redirect && Utility::handle_license_calls( 'is_license_valid', 'library', false ) ) {
			$disable_site_auto_redirect_toggle = '';
		}

		require_once Plugin_Files_Constants::TEMPLATE_SSO_REDIRECTION_SETTINGS;
	}
}
