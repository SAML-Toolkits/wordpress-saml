<?php
/**
 * Site Auto Redirection Handler.
 *
 * @package MOSAML\Module\Premium\Handler\Core
 */

namespace MOSAML\Module\Premium\Handler\Core;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\Module\Standard\Handler\Core\Site_Auto_Redirection_Handler as Standard_Site_Auto_Redirection_Handler;
use MOSAML\SRC\Utils\Utility;

/**
 * Site Auto Redirection Handler.
 */
class Site_Auto_Redirection_Handler extends Standard_Site_Auto_Redirection_Handler {

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

		if ( 'wp_login' !== $this->site_auto_redirection_option ) {
			return;
		}

		$redirect_url = site_url( '/wp-login.php' );
		wp_safe_redirect( $redirect_url );
		exit;
	}
}
