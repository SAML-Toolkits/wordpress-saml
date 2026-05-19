<?php
/**
 * Site auto redirection handler (standard module).
 *
 * @package miniorange-saml-20-single-sign-on
 */

namespace MOSAML\Module\Standard\Handler\Core;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\Module\Base\Handler\Core\Site_Auto_Redirection_Handler as Base_Site_Auto_Redirection_Handler;
use MOSAML\SRC\Utils\Utility;
use MOSAML\SRC\Constant\Plugin_Options;
use MOSAML\SRC\Utils\DB_Utils;
use MOSAML\SRC\Utils\Error_Success_Message;
use MOSAML\SRC\Constant\Error_Codes_Enums;

/**
 * Site Auto Redirection Handler.
 */
class Site_Auto_Redirection_Handler extends Base_Site_Auto_Redirection_Handler {

	/**
	 * Handle site auto redirection.
	 *
	 * @return void
	 */
	public function handle_site_auto_redirection() {
		if ( Utility::mo_saml_is_user_logged_in() ) {
			return;
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

		parent::handle_site_auto_redirection();

		$idp_id = DB_Utils::get_default_inserted_idp_details( 'id', DB_Utils::get_environment_details( 'id' ) );
		$where  = array(
			'option_name' => 'enable_rss_feed_access',
			'subsite_id'  => Utility::get_subsite_id_for_environment( DB_Utils::get_environment_details( 'id', true ) ),
			'idp_id'      => $idp_id,
		);

		if ( Utility::is_legacy_data_fallback_required() ) {
			$self_object = apply_filters( 'mosaml_legacy_data_fallback_object', $this, $where );

			$this->enable_rss_feed_access = $self_object->enable_rss_feed_access;
		} else {
			$record = DB_Utils::get_records(
				$this->get_table_name(),
				$where,
				true
			);
			if ( $record ) {
				$this->enable_rss_feed_access = $record->option_value;
			}
		}

		if ( 'checked' === $this->enable_rss_feed_access && is_feed() ) {
			return;
		}

		$where = array(
			'option_name' => 'enable_site_auto_redirect',
			'subsite_id'  => Utility::get_subsite_id_for_environment( DB_Utils::get_environment_details( 'id', true ) ),
			'idp_id'      => $idp_id,
		);

		if ( Utility::is_legacy_data_fallback_required() ) {
			$self_object = apply_filters( 'mosaml_legacy_data_fallback_object', $this, $where );

			$this->enable_site_auto_redirect = $self_object->enable_site_auto_redirect;
		} else {
			$record = DB_Utils::get_records(
				$this->get_table_name(),
				$where,
				true
			);
			if ( $record ) {
				$this->enable_site_auto_redirect = $record->option_value;
			}
		}

		$this->enable_site_auto_redirect = ! apply_filters( 'mosaml_pre_auto_redirection_internal', false ) ? $this->enable_site_auto_redirect : '';

		if ( 'checked' !== $this->enable_site_auto_redirect ) {
			return;
		}

		$where = array(
			'option_name' => 'site_auto_redirection_option',
			'subsite_id'  => Utility::get_subsite_id_for_environment( DB_Utils::get_environment_details( 'id', true ) ),
			'idp_id'      => $idp_id,
		);

		if ( Utility::is_legacy_data_fallback_required() ) {
			$self_object = apply_filters( 'mosaml_legacy_data_fallback_object', $this, $where );

			$this->site_auto_redirection_option = $self_object->site_auto_redirection_option;
		} else {
			$record = DB_Utils::get_records(
				$this->get_table_name(),
				$where,
				true
			);
			if ( $record ) {
				$this->site_auto_redirection_option = $record->option_value;
			}
		}
		if ( 'default_idp' !== $this->site_auto_redirection_option ) {
			return;
		}
		self::redirect_to_default_idp();
	}

	/**
	 * Redirect to default IDP from site.
	 *
	 * @return void
	 */
	protected function redirect_to_default_idp() {
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

		$current_page_url  = Utility::get_current_page_url();
		$current_page_path = wp_parse_url( $current_page_url, PHP_URL_PATH );

		if ( wp_parse_url( $current_page_url, PHP_URL_QUERY ) ) {
			$current_page_query = wp_parse_url( $current_page_url, PHP_URL_QUERY );
			$current_page_path  = $current_page_path . '?' . $current_page_query;
		}
		if ( wp_parse_url( $current_page_url, PHP_URL_FRAGMENT ) ) {
			$current_page_fragment = wp_parse_url( $current_page_url, PHP_URL_FRAGMENT );
			$current_page_path     = $current_page_path . '#' . $current_page_fragment;
		}

		$redirect_url = add_query_arg(
			array(
				'option'      => Plugin_Options::SAML_REQUEST_OPTION['SAML_USER_LOGIN'],
				'idp'         => $default_idp->idp_id,
				'redirect_to' => urlencode( $current_page_path ),
			),
			site_url( '/' )
		);
		wp_safe_redirect( $redirect_url );
		exit;
	}
}
