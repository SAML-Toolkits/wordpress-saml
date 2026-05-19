<?php
/**
 * Hook_Gate_Keeper class.
 *
 * @package miniorange-saml-20-single-sign-on/src/abstract
 */

namespace MOSAML\SRC\Abstracts;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Hook_Gate_Keeper class.
 */
abstract class Hook_Gate_Keeper {

	/**
	 * Internal hook callbacks.
	 *
	 * @var array
	 */
	private static $internal_hook_callbacks = array();

	/**
	 * Initialize the hook gatekeeper.
	 *
	 * @return void
	 */
	public static function init() {
		self::register_actions();
		self::register_filters();
	}

	/**
	 * Get the added actions.
	 *
	 * @return array The actions.
	 */
	abstract protected static function get_added_actions();

	/**
	 * Get the added filters.
	 *
	 * @return array The filters.
	 */
	abstract protected static function get_added_filters();

	/**
	 * Get the actions.
	 *
	 * @return array The actions.
	 */
	abstract protected static function get_allowed_actions();

	/**
	 * Get the filters.
	 *
	 * @return array The filters.
	 */
	abstract protected static function get_allowed_filters();

	/**
	 * Check if the hook is allowed.
	 *
	 * @param string $internal The internal hook.
	 * @param string $type The type of hook.
	 * @return bool True if the hook is allowed, false otherwise.
	 */
	abstract protected static function is_allowed( $internal, $type );

	/**
	 * Register the actions.
	 *
	 * @return void
	 */
	private static function register_actions() {
		foreach ( static::get_added_actions() as $internal ) {
			if ( ! static::is_allowed( $internal, 'action' ) ) {
				self::remove_internal_hook_callbacks( $internal, 'action' );
				continue;
			}
			$public                                     = static::get_allowed_actions()[ $internal ];
			self::$internal_hook_callbacks[ $internal ] =
			fn ( ...$args ) => self::dispatch_action( $internal, $public, ...$args );

			add_action(
				$internal,
				self::$internal_hook_callbacks[ $internal ],
				PHP_INT_MIN,
				PHP_INT_MAX
			);
		}
	}

	/**
	 * Register the filters.
	 *
	 * @return void
	 */
	private static function register_filters() {
		foreach ( static::get_added_filters() as $internal ) {
			if ( ! static::is_allowed( $internal, 'filter' ) ) {
				self::remove_internal_hook_callbacks( $internal, 'filter' );
				continue;
			}
			$public_hook = static::get_allowed_filters()[ $internal ];
			add_filter(
				$internal,
				fn( $value, ...$args ) => self::dispatch_filter( $internal, $public_hook, $value, ...$args ),
				PHP_INT_MIN,
				PHP_INT_MAX
			);
		}
	}

	/**
	 * Dispatch the action.
	 *
	 * @param string $internal The internal hook.
	 * @param string $public_hook The public hook.
	 * @param mixed  ...$args The arguments.
	 * @return void
	 */
	private static function dispatch_action( $internal, $public_hook, ...$args ) {
		self::remove_internal_hook_callbacks( $internal, 'action' );
		if ( ! static::is_allowed( $internal, 'action' ) ) {
			return;
		}
		// phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.DynamicHooknameFound -- Dynamic public hook for integrations.
		do_action( $public_hook, ...$args );
	}

	/**
	 * Dispatch the filter.
	 *
	 * @param string $internal The internal hook.
	 * @param string $public_hook The public hook.
	 * @param mixed  $value The value.
	 * @param mixed  ...$args The arguments.
	 * @return mixed The value.
	 */
	private static function dispatch_filter( $internal, $public_hook, $value, ...$args ) {
		self::remove_internal_hook_callbacks( $internal, 'filter' );
		if ( ! static::is_allowed( $internal, 'filter' ) ) {
			return $value;
		}
		// phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.DynamicHooknameFound -- Dynamic public hook for integrations.
		$value = apply_filters( $public_hook, $value, ...$args );
		return $value;
	}

	/**
	 * Remove the internal hook callbacks.
	 *
	 * @param string $internal The internal hook.
	 * @param string $type The type of hook.
	 * @return void
	 */
	private static function remove_internal_hook_callbacks( $internal, $type ) {
		global $wp_filter;

		if ( empty( $wp_filter[ $internal ] ) ) {
			return;
		}

		$hook = $wp_filter[ $internal ];

		foreach ( $hook->callbacks as $priority => $callbacks ) {
			foreach ( $callbacks as $callback ) {
				if ( isset( self::$internal_hook_callbacks[ $internal ] ) && $callback['function'] === self::$internal_hook_callbacks[ $internal ] ) {
					continue;
				}
				'action' === $type ?
				remove_action(
					$internal,
					$callback['function'],
					$priority
				) :
				remove_filter(
					$internal,
					$callback['function'],
					$priority
				);
			}
		}
	}
}
