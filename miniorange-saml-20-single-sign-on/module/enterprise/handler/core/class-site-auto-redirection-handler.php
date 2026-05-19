<?php
/**
 * Site Auto Redirection Handler.
 *
 * @package MOSAML\Module\Enterprise\Handler\Core
 */

namespace MOSAML\Module\Enterprise\Handler\Core;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\Module\Premium\Handler\Core\Site_Auto_Redirection_Handler as Premium_Site_Auto_Redirection_Handler;
use MOSAML\SRC\Utils\Utility;
use MOSAML\SRC\Utils\DB_Utils;

/**
 * Site Auto Redirection Handler.
 */
class Site_Auto_Redirection_Handler extends Premium_Site_Auto_Redirection_Handler {

	/**
	 * Handle site auto redirection.
	 *
	 * @return void
	 */
	public function handle_site_auto_redirection() {
		if ( Utility::mo_saml_is_user_logged_in() ) {
			return;
		}

		parent::handle_site_auto_redirection();

		if ( 'checked' === $this->enable_rss_feed_access && is_feed() ) {
			return;
		}

		if ( 'checked' !== $this->enable_site_auto_redirect ) {
			return;
		}

		if ( 'public_page' !== $this->site_auto_redirection_option ) {
			return;
		}

		$record = DB_Utils::get_records(
			$this->get_table_name(),
			array(
				'option_name' => 'public_page_url',
				'subsite_id'  => Utility::get_subsite_id_for_environment( DB_Utils::get_environment_details( 'id', true ) ),
				'idp_id'      => DB_Utils::get_default_inserted_idp_details( 'id', DB_Utils::get_environment_details( 'id' ) ),
			),
			true
		);
		if ( $record ) {
			$this->public_page_url = rtrim( $record->option_value, '/' ) . '/';
		}
		if ( Utility::get_current_page_url() === $this->public_page_url ) {
			return;
		}
		if ( Utility::is_3rd_party_url( $this->public_page_url ) ) {
			parent::redirect_to_default_idp();
		}
		wp_safe_redirect( $this->public_page_url );
		exit;
	}
}
