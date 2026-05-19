<?php
/**
 * Environment Object.
 *
 * @package    MOSAML
 * @subpackage MOSAML/src/handler/migration/mapper/object
 */
// phpcs:ignoreFile WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedClassFound -- Already added class.


if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class EnvironmentObject
 */
class EnvironmentObject {

	/**
	 * The WordPress site URL.
	 *
	 * @var string
	 */
	private $wp_site_url;

	/**
	 * The plugin settings.
	 *
	 * @var array
	 */
	private $plugin_settings = array();

	/**
	 * Get the environment object as an array.
	 *
	 * @return array The environment object as an array.
	 */
	public function getEnvironmentObjectToArray() {
		return get_object_vars( $this );
	}

	/**
	 * Constructor.
	 *
	 * @param string $wp_site_url The WordPress site URL.
	 */
	public function __construct( $wp_site_url ) {
		$this->wp_site_url = $wp_site_url;
	}

	/**
	 * Get the WordPress site URL.
	 *
	 * @return string The WordPress site URL.
	 */
	public function getWpSiteUrl() {
		return $this->wp_site_url;
	}

	/**
	 * Set the WordPress site URL.
	 *
	 * @param string $wp_site_url The WordPress site URL.
	 */
	public function setWpSiteUrl( $wp_site_url ) {
		$this->wp_site_url = $wp_site_url;
	}

	/**
	 * Get the plugin settings.
	 *
	 * @return array The plugin settings.
	 */
	public function getPluginSettings() {
		return $this->plugin_settings;
	}

	/**
	 * Set the plugin settings.
	 *
	 * @param array $plugin_settings The plugin settings.
	 * @return void
	 */
	public function setPluginSettings( $plugin_settings ) {
		$this->plugin_settings = $plugin_settings;
	}
}
