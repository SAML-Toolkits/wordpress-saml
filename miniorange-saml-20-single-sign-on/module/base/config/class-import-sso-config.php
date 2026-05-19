<?php
/**
 * Base Module - Import SSO Configuration Class
 *
 * Handles SSO configuration data import for the base module.
 *
 * @package MOSAML\Module\Base\Config
 * @since 1.0.0
 */

namespace MOSAML\Module\Base\Config;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\SRC\Constant\Constants;

/**
 * Base Import SSO Configuration Class
 */
class Import_SSO_Config {

	/**
	 * Get the database table name
	 *
	 * @return string The table name
	 */
	protected function get_table_name() {
		return Constants::DATABASE_TABLE_NAMES['sso_settings'];
	}

	/**
	 * Subsite ID
	 *
	 * @var int
	 */
	public $subsite_id;

	/**
	 * Relay state
	 *
	 * @var string
	 */
	public $relay_state = '';

	/**
	 * Redirect IDP
	 *
	 * @var string
	 */
	public $redirect_idp = '';

	/**
	 * Force authentication
	 *
	 * @var string
	 */
	public $force_authentication = '';

	/**
	 * Enable access RSS
	 *
	 * @var string
	 */
	public $enable_access_rss = '';

	/**
	 * Auto redirect
	 *
	 * @var string
	 */
	public $auto_redirect = '';

	/**
	 * Allow WP signin
	 *
	 * @var string
	 */
	public $allow_wp_signin = '';

	/**
	 * Custom login button
	 *
	 * @var string
	 */
	public $custom_login_button = '';

	/**
	 * Custom greeting text
	 *
	 * @var string
	 */
	public $custom_greeting_text = '';

	/**
	 * Custom greeting name
	 *
	 * @var string
	 */
	public $custom_greeting_name = '';

	/**
	 * Custom logout button
	 *
	 * @var string
	 */
	public $custom_logout_button = '';

	/**
	 * SAML login widget
	 *
	 * @var string
	 */
	public $saml_login_widget = '';

	/**
	 * SSO button
	 *
	 * @var string
	 */
	public $sso_button = '';

	/**
	 * Keep configuration intact
	 *
	 * @var string
	 */
	public $keep_configuration_intact = '';

	/**
	 * SSO button config
	 *
	 * @var string
	 */
	public $sso_button_config = '';

	/**
	 * Widget config
	 *
	 * @var string
	 */
	public $widget_config = '';

	/**
	 * Shortcode login text
	 *
	 * @var string
	 */
	public $shortcode_login_text = '';

	/**
	 * IDP shortcode login text
	 *
	 * @var string
	 */
	public $idp_shortcode_login_text = '';

	/**
	 * Hide WP login
	 *
	 * @var string
	 */
	public $hide_wp_login = '';

	/**
	 * SSO show user
	 *
	 * @var string
	 */
	public $sso_show_user = '';
}
