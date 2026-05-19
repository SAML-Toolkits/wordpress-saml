<?php
/**
 * Admin Init Controller for SAML plugin.
 *
 * @package miniorange-saml-20-single-sign-on
 */

namespace MOSAML\SRC\Controller;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\SRC\Utils\Utility;
use MOSAML\Traits\Instance;
use MOSAML\SRC\Handler\Import_Export\Import_Config_Handler;
use MOSAML\SRC\Utils\Feature_Control;
use MOSAML\SRC\Utils\Error_Success_Message;
use MOSAML\SRC\Database\Database_Migrator;
use MOSAML\SRC\Utils\DB_Utils;
use MOSAML\SRC\Constant\Constants;
use MOSAML\SRC\Handler\Import_Export\Import_Export_Config_Handler;
use MOSAML\SRC\Constant\Error_Codes_Enums;
use MOSAML\SRC\Handler\UI\Feedback_Form_Handler;

/**
 * Admin Init Controller class.
 *
 * Handles admin initialization actions and form submissions.
 */
class Admin_Init_Controller {

	use Instance;

	/**
	 * Initialize admin actions.
	 *
	 * @return void
	 */
	public function admin_init_actions() {
		$this->form_submission();
		$this->plugin_update_actions();
		$this->handle_test_config_error();
	}

	/**
	 * Handle test config error.
	 *
	 * @return void
	 */
	private function handle_test_config_error() {
		$option = Utility::sanitize_request_data( 'option' );
		$key    = Utility::sanitize_request_data( 'key' );
		if ( ! $key || ! $option ) {
			return;
		}
		$error_code = str_replace( 'mosaml_error_', '', $option );
		$details    = get_transient( $key );
		if ( $details ) {
			delete_transient( $key );
			Error_Success_Message::show_test_config_admin_error_window( Error_Codes_Enums::$error_codes[ strtoupper( $error_code ) ], json_decode( $details, true ) );
		}
	}
	/**
	 * Handle form submissions.
	 *
	 * @return void
	 */
	private function form_submission() {
		if ( ! isset( $_POST['option'] ) ) {
			return;
		}

		Utility::start_output_buffering();

		$option = Utility::sanitize_post_data( 'option' );

		if ( false === strpos( $option, 'mosaml' ) || ! check_admin_referer( $option ) || ! current_user_can( 'manage_options' ) ) {
			Utility::clean_output_buffer();
			return;
		}

		if ( ! $this->is_license_valid_for_action( $option ) ) {
			Error_Success_Message::show_admin_notice( 'Please verify your license to configure these settings.' );
			Utility::clean_output_buffer();
			return;
		}

		if ( $this->is_no_idp_configured_for_action( $option ) ) {
			Error_Success_Message::show_admin_notice( 'Please configure at least one Identity Provider to access this feature.' );
			Utility::clean_output_buffer();
			return;
		}

		switch ( $option ) {
			case 'mosaml_upload_metadata_file':
				$handler = Utility::get_handler_object( 'sp_setup_data', true, 'admin' );
				break;
			case 'mosaml_fetch_metadata_url':
				$handler = Utility::get_handler_object( 'sp_setup_data', true, 'admin' );
				break;
			case 'mosaml_login_widget_saml_save_settings':
				$handler = Utility::get_handler_object( 'sp_setup_data', true, 'admin' );
				break;
			case 'mosaml_login_widget_saml_metadata_sync':
				$handler = Utility::get_handler_object( 'metadata_sync_data', true, 'Admin' );
				break;
			case 'mosaml_edit_sp_metadata':
				$handler = Utility::get_handler_object( 'sp_endpoints_data', true, 'Admin' );
				break;
			case 'mosaml_download_metadata':
				$sp_metadata_handler = Utility::get_handler_object( 'sp_metadata_data', true, 'admin' );
				$sp_metadata_handler->download_sp_metadata();
				break;
			case 'mosaml_make_idp_default':
				$idp_id           = Utility::sanitize_post_data( 'mosaml_idp_id_to_make_default' );
				$sp_setup_handler = Utility::get_handler_object( 'sp_setup_data', true, 'admin' );
				$sp_setup_handler->handle_idp_list_actions( 'default_idp', $idp_id );
				break;
			case 'mosaml_bulk_action_confirmation':
				$bulk_action        = Utility::sanitize_post_data( 'bulk_action' );
				$bulk_action_record = Utility::sanitize_post_data( 'bulk_action_record' );
				$sp_setup_handler   = Utility::get_handler_object( 'sp_setup_data', true, 'admin' );
				$sp_setup_handler->handle_idp_list_actions( $bulk_action, $bulk_action_record );
				break;
			case 'mosaml_download_cert':
				$sp_metadata_handler = Utility::get_handler_object( 'sp_metadata_data', true, 'admin' );
				$sp_metadata_handler->download_certificate();
				break;
			case 'mosaml_update_xml_organization_metadata':
				$handler = Utility::get_handler_object( 'sp_organization_data', true, 'admin' );
				break;
			case 'mosaml_attribute_mapping_form':
				$handler = Utility::get_handler_object( 'attribute_mapping_data', true, 'admin' );
				break;
			case 'mosaml_role_mapping_form':
				$handler = Utility::get_handler_object( 'role_assignment_settings_data', true, 'admin' );
				$handler->validate_and_save_data();
				$handler = Utility::get_handler_object( 'role_mapping_data', true, 'admin' );
				break;
			case 'mosaml_role_mapping_advanced_settings_form':
				$handler = Utility::get_handler_object( 'role_mapping_advanced_settings_data', true, 'admin' );
				break;
			case 'mosaml_site_auto_redirection':
				$handler = Utility::get_handler_object( 'site_auto_redirection_data', true, 'admin' );
				break;
			case 'mosaml_rss_feed_access':
				$handler = Utility::get_handler_object( 'rss_feed_access_data', true, 'admin' );
				break;
			case 'mosaml_force_authentication':
				$handler = Utility::get_handler_object( 'force_authentication_data', true, 'admin' );
				break;
			case 'mosaml_backdoor_url_login':
				$handler = Utility::get_handler_object( 'backdoor_url_login_data', true, 'admin' );
				break;
			case 'mosaml_enable_hide_wp_login_option':
				$handler = Utility::get_handler_object( 'hide_wp_login_data', true, 'admin' );
				break;
			case 'mosaml_login_page_auto_redirection':
				$handler = Utility::get_handler_object( 'login_page_auto_redirection_data', true, 'admin' );
				break;
			case 'mosaml_domain_mapping':
				$handler = Utility::get_handler_object( 'domain_mapping_data', true, 'admin' );
				break;
			case 'mosaml_relay_state':
				$handler = Utility::get_handler_object( 'relay_state_data', true, 'admin' );
				break;
			case 'mosaml_sso_button_options':
				$handler = Utility::get_handler_object( 'sso_button_data', true, 'admin' );
				break;
			case 'mosaml_shortcode_option':
				$handler = Utility::get_handler_object( 'shortcode_data', true, 'admin' );
				break;
			case 'mosaml_reset_sso_button_option':
				$sso_button_handler = Utility::get_handler_object( 'sso_button_data', true, 'admin' );
				$sso_button_handler->delete_data();
				break;
			case 'mosaml_login_shortcode_widget_saml_settings':
				$handler = Utility::get_handler_object( 'shortcode_widget_data', true, 'admin' );
				break;
			case 'mosaml_add_custom_certificate':
				$handler = Utility::get_handler_object( 'certificate_data', true, 'admin' );
				break;
			case 'mosaml_sso_show_user':
				$handler = Utility::get_handler_object( 'sso_user_data', true, 'admin' );
				break;
			case 'mosaml_add_custom_messages':
				$handler = Utility::get_handler_object( 'custom_messages_data', true, 'admin' );
				break;
			case 'mosaml_keep_settings_on_deletion':
				$keep_settings_value = Utility::sanitize_post_data( 'mo_saml_keep_settings_intact' );
				update_option( Constants::KEEP_SETTINGS_OPTION_NAME, $keep_settings_value );
				if ( 'checked' === $keep_settings_value ) {
					Error_Success_Message::show_admin_notice( 'Keep Settings Intact option has been enabled.', 'SUCCESS' );
				} else {
					Error_Success_Message::show_admin_notice( 'Keep Settings Intact option has been disabled.', 'SUCCESS' );
				}
				break;
			case 'mosaml_reset_attribute_mapping':
				$data_handler = Utility::get_handler_object( 'attribute_mapping_data', true, 'admin' );
				$data_handler->delete_data();
				break;
			case 'mosaml_reset_role_mapping':
				$data_handler = Utility::get_handler_object( 'role_mapping_data', true, 'admin' );
				$data_handler->delete_data();
				$role_assignment_settings_handler = Utility::get_handler_object( 'role_assignment_settings_data', true, 'admin' );
				$role_assignment_settings_handler->delete_data();
				break;
			case 'mosaml_reset_role_mapping_advanced_settings':
				$data_handler = Utility::get_handler_object( 'role_mapping_advanced_settings_data', true, 'admin' );
				$data_handler->delete_data();
				break;
			case 'mosaml_debug_logger':
				$handler = Utility::get_handler_object( 'debug_logger_data', true, 'admin' );
				break;
			case 'mosaml_enable_plugin_backup_on_upgrade':
				$enable_backup = Utility::sanitize_post_data( 'mo_saml_enable_backup_settings' );
				update_option( Constants::ENABLE_BACKUP_SETTINGS, ! empty( $enable_backup ) ? 'checked' : '' );
				if ( 'checked' === $enable_backup ) {
					Error_Success_Message::show_admin_notice( 'Plugin Backup on Upgrade has been enabled.', 'SUCCESS' );
				} else {
					Error_Success_Message::show_admin_notice( 'Plugin Backup on Upgrade has been disabled.', 'SUCCESS' );
				}
				break;
			case 'mosaml_multiple_environment':
				if ( MOSAML_VERSION >= 4 ) {
					$enable_multiple_env_value = Utility::sanitize_post_data( 'enable_multiple_environments' );
					update_option( Constants::ENABLE_MULTIPLE_ENVIRONMENTS_OPTION_NAME, $enable_multiple_env_value );
					if ( 'checked' === $enable_multiple_env_value ) {
						Error_Success_Message::show_admin_notice( 'Multiple Environments feature has been enabled.', 'SUCCESS' );
					} else {
						Error_Success_Message::show_admin_notice( 'Multiple Environments feature has been disabled.', 'SUCCESS' );
					}
				}
				break;
			case 'mosaml_save_environment':
				$handler = Utility::get_handler_object( 'multiple_environments_data', true, 'admin' );
				break;
			case 'mosaml_change_environment':
				$handler = Utility::get_handler_object( 'multiple_environments_data', true, 'admin' );
				$handler->change_environment();
				break;
			case 'mosaml_clear_attrs_list':
				$data_handler = Utility::get_handler_object( 'sp_setup_data', true, 'admin' );
				$data_handler->clear_test_config_attributes();
				break;
			case 'mosaml_register_customer':
				$handler = Utility::get_handler_object( 'account_settings', true, 'admin' );
				break;
			case 'mosaml_verify_customer':
				Utility::handle_license_calls( 'verify_customer', 'both' );
				break;
			case 'mosaml_verify_license':
				Utility::handle_license_calls( 'verify_license', 'library' );
				break;
			case 'mosaml_remove_account':
				Utility::handle_license_calls( 'remove_account', 'both' );
				break;
			case 'mosaml_back_license_verification':
				Utility::handle_license_calls( 'remove_user_login', 'both' );
				break;
			case 'mosaml_sync_license':
				Utility::handle_license_calls( 'sync_license', 'library' );
				break;
			case 'mosaml_skip_feedback':
				$deactivate_url = admin_url( 'plugins.php?action=deactivate&plugin=' . rawurlencode( plugin_basename( MOSAML_PLUGIN_FILE ) ) . '&_wpnonce=' . wp_create_nonce( 'deactivate-plugin_' . plugin_basename( MOSAML_PLUGIN_FILE ) ) );
				wp_safe_redirect( $deactivate_url );
				exit;
			case 'mosaml_feedback':
				$feedback_handler = new Feedback_Form_Handler();
				$feedback_handler->handle_feedback_submission();
				break;
			case 'mosaml_update_database':
				$this->update_database();
				break;
			case 'mosaml_setup_database':
				$this->setup_database();
				break;
			case 'mosaml_contact_us_query_option':
				$handler = Utility::contact_us_for_support();
				break;
			case 'mosaml_import':
				$config_handler = new Import_Config_Handler();
				$config_handler->handle_config_import();
				break;
			case 'mosaml_export_configuration':
				Import_Export_Config_Handler::export_plugin_configuration();
				break;
			case 'mosaml_dismiss_database_update_required':
				update_option( Constants::DISMISSED_DATABASE_UPDATE_REQUIRED_NOTICE_OPTION_NAME, true );
				break;
			case 'mosaml_fix_test_config_issue':
				$handler = Utility::get_handler_object( 'test_config_data', true, 'admin' );
				break;
			case 'mosaml_download_new_cert':
				$sp_metadata_handler = Utility::get_handler_object( 'sp_metadata_data', true, 'admin' );
				$sp_metadata_handler->download_certificate( true );
				break;
			case 'mosaml_download_new_metadata':
				$sp_metadata_handler = Utility::get_handler_object( 'sp_metadata_data', true, 'admin' );
				$sp_metadata_handler->download_sp_metadata( true );
				break;
			case 'mosaml_upgrade_new_certificate':
				$certificate_data_handler = Utility::get_handler_object( 'certificate_data', true, 'admin' );
				$certificate_data_handler->upgrade_new_certificate();
				break;
			case 'mosaml_enable_complete_logout_option':
				$handler = Utility::get_handler_object( 'logout_all_sessions_data', true, 'admin' );
				break;
		}

		if ( ! empty( $handler ) && method_exists( $handler, 'validate_and_save_data' ) ) {
			$handler->validate_and_save_data();
		}

		Utility::clean_output_buffer();
	}

	/**
	 * Check if the license is valid for the given action.
	 *
	 * @param string $option The action being performed.
	 * @return bool True if the license is valid or the action is exempt, false otherwise.
	 */
	private function is_license_valid_for_action( $option ) {
		$skip_license_check = array(
			'mosaml_contact_us_query_option',
			'mosaml_register_customer',
			'mosaml_verify_customer',
			'mosaml_verify_license',
			'mosaml_sync_license',
			'mosaml_remove_account',
			'mosaml_back_license_verification',
			'mosaml_keep_settings_on_deletion',
			'mosaml_update_database',
			'mosaml_setup_database',
			'mosaml_debug_logger',
			'mosaml_enable_plugin_backup_on_upgrade',
			'mosaml_export_configuration',
			'mosaml_change_environment',
			'mosaml_dismiss_database_update_required',
			'mosaml_feedback',
			'mosaml_skip_feedback',
		);

		if ( in_array( $option, $skip_license_check, true ) || 1 === MOSAML_VERSION ) {
			return true;
		}

		if ( Feature_Control::check_is_license_valid() ) {
			return true;
		}

		return false;
	}

	/**
	 * Check if no IDP is configured for the given action.
	 *
	 * @param string $option The action being performed.
	 * @return bool True if no IDP check is exempted for the action, false otherwise.
	 */
	private function is_no_idp_configured_for_action( $option ) {
		$no_idp_check_exemptions = array(
			'mosaml_upload_metadata_file',
			'mosaml_fetch_metadata_url',
			'mosaml_login_widget_saml_save_settings',
			'mosaml_login_widget_saml_metadata_sync',
			'mosaml_edit_sp_metadata',
			'mosaml_download_metadata',
			'mosaml_make_idp_default',
			'mosaml_bulk_action_confirmation',
			'mosaml_download_cert',
			'mosaml_update_xml_organization_metadata',
			'mosaml_add_custom_certificate',
			'mosaml_sso_show_user',
			'mosaml_add_custom_messages',
			'mosaml_multiple_environment',
			'mosaml_save_environment',
			'mosaml_change_environment',
			// redirection settings which needs to be accessible even if no IDP is configured.
			'mosaml_site_auto_redirection',
			'mosaml_rss_feed_access',
			'mosaml_force_authentication',
			'mosaml_login_page_auto_redirection',
			'mosaml_backdoor_url_login',
			'mosaml_domain_mapping',
			'mosaml_add_custom_messages',
			'mosaml_sso_show_user',
			'mosaml_add_custom_certificate',
			// below are forms which do not require license & IDP to be configured.
			'mosaml_contact_us_query_option',
			'mosaml_register_customer',
			'mosaml_verify_customer',
			'mosaml_verify_license',
			'mosaml_sync_license',
			'mosaml_remove_account',
			'mosaml_back_license_verification',
			'mosaml_keep_settings_on_deletion',
			'mosaml_update_database',
			'mosaml_setup_database',
			'mosaml_debug_logger',
			'mosaml_enable_plugin_backup_on_upgrade',
			'mosaml_export_configuration',
			'mosaml_import',
			'mosaml_dismiss_database_update_required',
			'mosaml_feedback',
			'mosaml_skip_feedback',
		);

		if ( ! in_array( $option, $no_idp_check_exemptions, true ) ) {
			$selected_environment_id = DB_Utils::get_environment_details( 'id', false );
			if ( Utility::mo_saml_is_no_idps_configured( $selected_environment_id ) ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Update the database.
	 *
	 * @return void
	 */
	private function update_database() {
		update_option( Constants::DATABASE_UPDATE_STATUS, 'started' );
		$result = DB_Utils::initialize_database();
		if ( ! $result ) {
			update_option( Constants::DATABASE_UPDATE_STATUS, 'failed' );
			Error_Success_Message::show_admin_notice( 'Failed to update the database. Please try again.' );
			return;
		}
		update_option( Constants::DATABASE_UPDATE_STATUS, 'completed' );
		Error_Success_Message::show_admin_notice( 'Database updated successfully.', 'SUCCESS' );
	}

	/**
	 * Setup the database.
	 *
	 * @return void
	 */
	private function setup_database() {
		$latest = Database_Migrator::get_latest_migration_version();
		if ( null === $latest ) {
			Error_Success_Message::show_admin_notice( 'Failed to update the database. Please try again.' );
			return;
		}

		if ( DB_Utils::all_tables_exist() && version_compare( DB_Utils::get_current_db_version(), $latest, '>=' ) ) {
			if ( ! DB_Utils::initialize_tables_data() ) {
				Error_Success_Message::show_admin_notice( 'Failed to add the default entries into the database tables.' );
				return;
			}

			DB_Utils::initialize_default_plugin_options();
		} elseif ( ! DB_Utils::initialize_database() ) {
			Error_Success_Message::show_admin_notice( 'Failed to add the default plugin options.' );
			return;
		}

		Error_Success_Message::show_admin_notice( 'Database setup completed successfully.', 'SUCCESS' );
	}

	/**
	 * Handle plugin update actions.
	 *
	 * @return void
	 */
	private function plugin_update_actions() {
		$update_framework = Utility::handle_license_calls( 'update_framework_instance', 'library' );
		if ( $update_framework ) {
			$plugin_slug = plugin_basename( dirname( __DIR__, 2 ) . '/login.php' );
			add_action( "in_plugin_update_message-{$plugin_slug}", array( $update_framework, 'plugin_update_message' ), 10, 2 );
			add_action( 'admin_notices', array( $update_framework, 'dismiss_notice' ), 50 );
		}
	}
}
