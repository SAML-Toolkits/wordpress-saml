<?php
/**
 * Cache Handler.
 *
 * @package MOSAML\SRC\Database
 */

namespace MOSAML\SRC\Database;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Cache Handler.
 *
 * @package MOSAML\SRC\Database
 */
class Cache_Handler {

	/**
	 * Get the cached data.
	 *
	 * @param string $key The key of the cached data.
	 * @return mixed The cached data.
	 */
	public static function get( $key ) {
		return wp_cache_get( $key );
	}

	/**
	 * Set the cached data.
	 *
	 * @param string $key The key of the cached data.
	 * @param mixed  $data The data to cache.
	 * @param int    $expiration The expiration time in seconds.
	 * @return bool True if the data was set, false otherwise.
	 */
	public static function set( $key, $data, $expiration = 600 ) {
		return wp_cache_set( $key, $data, '', $expiration );
	}

	/**
	 * Delete the cached data.
	 *
	 * @param string $key The key of the cached data.
	 * @return bool True if the data was deleted, false otherwise.
	 */
	public static function delete( $key ) {
		return wp_cache_delete( $key );
	}
}
