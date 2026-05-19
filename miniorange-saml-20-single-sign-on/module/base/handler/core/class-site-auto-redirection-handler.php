<?php
/**
 * Site auto redirection handler (base module).
 *
 * @package miniorange-saml-20-single-sign-on
 */

namespace MOSAML\Module\Base\Handler\Core;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\SRC\Constant\Constants;

/**
 * Site Auto Redirection Handler.
 */
class Site_Auto_Redirection_Handler {

	/**
	 * Enable auto redirect.
	 *
	 * @var string|null
	 */
	public $enable_site_auto_redirect;

	/**
	 * Auto redirection option.
	 *
	 * @var string|null
	 */
	public $site_auto_redirection_option;

	/**
	 * Enable RSS feed access.
	 *
	 * @var string|null
	 */
	public $enable_rss_feed_access;

	/**
	 * Public page URL.
	 *
	 * @var string|null
	 */
	public $public_page_url;

	/**
	 * Get table name.
	 *
	 * @return string
	 */
	public function get_table_name() {
		return Constants::DATABASE_TABLE_NAMES['sso_settings'];
	}

	/**
	 * Handle site auto redirection.
	 *
	 * @return void
	 */
	public function handle_site_auto_redirection() {
		$this->public_page_url              = site_url( '/' );
		$this->site_auto_redirection_option = 'default_idp';
	}
}
