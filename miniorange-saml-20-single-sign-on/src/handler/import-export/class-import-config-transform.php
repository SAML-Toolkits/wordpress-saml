<?php
/**
 * Import Config Transform.
 *
 * @package MOSAML\SRC\Handler\Import_Export
 */

namespace MOSAML\SRC\Handler\Import_Export;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\Traits\Instance;
use MOSAML\SRC\Constant\Constants;

/**
 * Import Config Transform.
 */
class Import_Config_Transform {

	use Instance;

	/**
	 * Invert the checked value.
	 *
	 * @param object       $handler_obj The handler object.
	 * @param string       $key The key of the configuration.
	 * @param array|string $value The value to invert.
	 * @return array|string The inverted value.
	 */
	public function invert_checked( $handler_obj, $key, $value ) {
		return ( 'checked' === $value ) ? '' : 'checked';
	}

	/**
	 * Transform 'true' string to 'checked'.
	 *
	 * @param object       $handler_obj The handler object.
	 * @param string       $key The key of the configuration.
	 * @param array|string $value The value to transform.
	 * @return array|string The transformed value.
	 */
	public function true_to_checked( $handler_obj, $key, $value ) {
		return ( true === (bool) $value && ( 'false' !== $value && 'unchecked' !== $value ) ) ? 'checked' : '';
	}

	/**
	 * Set the name ID format.
	 *
	 * @param object       $handler_obj The handler object.
	 * @param string       $key The key of the configuration.
	 * @param array|string $value The value to set the name ID format.
	 * @return array|string The value of the name ID format.
	 */
	public function prepare_name_id_format( $handler_obj, $key, $value ) {
		if ( empty( $value ) ) {
			return Constants::NAMEID_FORMATS['unspecified'];
		}

		$valid_nameid_formats = array_values( Constants::NAMEID_FORMATS );

		if ( in_array( $value, $valid_nameid_formats, true ) ) {
			return $value;
		}

		foreach ( $valid_nameid_formats as $valid_format ) {
			if ( strpos( $valid_format, $value ) !== false ) {
				return $valid_format;
			}
		}

		return Constants::NAMEID_FORMATS['unspecified'];
	}

	/**
	 * Add to widget config.
	 *
	 * @param object       $handler_obj The handler object.
	 * @param string       $key The key of the configuration.
	 * @param array|string $value The value to add to the widget config.
	 * @return array The widget config.
	 */
	public function add_to_widget_config( $handler_obj, $key, $value ) {
		$widget_config = ! empty( $handler_obj->widget_config ) ? $handler_obj->widget_config : array();
		switch ( $key ) {
			case 'custom_login_button':
			case 'custom_login_text':
				$widget_config['custom_login_text'] = $value;
				break;
			case 'custom_greeting_text':
				$widget_config['custom_greeting_text'] = $value;
				break;
			case 'custom_greeting_name':
			case 'greeting_name':
				$widget_config['greeting_name'] = $value;
				break;
			case 'custom_logout_button':
			case 'custom_logout_text':
				$widget_config['custom_logout_text'] = $value;
				break;
			default:
				break;
		}
		return $widget_config;
	}

	/**
	 * Transform 'true' string to 'active'.
	 *
	 * @param object       $handler_obj The handler object.
	 * @param string       $key The key of the configuration.
	 * @param array|string $value The value to transform.
	 * @return string The transformed value.
	 */
	public function true_to_active( $handler_obj, $key, $value ) {
		return ( true === (bool) $value ) ? 'active' : 'inactive';
	}

	/**
	 * Transform 'true' string to 'default_idp'.
	 *
	 * @param object       $handler_obj The handler object.
	 * @param string       $key The key of the configuration.
	 * @param array|string $value The value to transform.
	 * @return string The transformed value.
	 */
	public function true_to_default_idp( $handler_obj, $key, $value ) {
		return ( true === (bool) $value ) ? 'default_idp' : '';
	}

	/**
	 * Transform 'true' string to 'wp_login'.
	 *
	 * @param object       $handler_obj The handler object.
	 * @param string       $key The key of the configuration.
	 * @param array|string $value The value to transform.
	 * @return string The transformed value.
	 */
	public function true_to_wp_login( $handler_obj, $key, $value ) {
		return ( true === (bool) $value ) ? 'wp_login' : '';
	}

	/**
	 * Transform 'true' string to 'public_page'.
	 *
	 * @param object       $handler_obj The handler object.
	 * @param string       $key The key of the configuration.
	 * @param array|string $value The value to transform.
	 * @return string The transformed value.
	 */
	public function true_to_public_page( $handler_obj, $key, $value ) {
		return ( true === (bool) $value ) ? 'public_page' : '';
	}

	/**
	 * Transform empty value to default.
	 *
	 * @param object       $handler_obj The handler object.
	 * @param string       $key The key of the configuration.
	 * @param array|string $value The value to transform.
	 * @return string The transformed value.
	 */
	public function empty_to_default( $handler_obj, $key, $value ) {
		if ( ! empty( $value ) ) {
			return $value;
		}

		switch ( $key ) {
			case 'sp_base_url':
				$site_url = get_site_url();
				return $site_url;
			case 'sp_entity_id':
				$site_url = get_site_url();
				return $site_url . Constants::SP_ENTITY_ID;
			default:
				return $value;
		}
	}

	/**
	 * Format custom attributes.
	 *
	 * @param object       $handler_obj The handler object.
	 * @param string       $key The key of the configuration.
	 * @param array|string $value The value to format.
	 * @return array The formatted value.
	 */
	public function format_custom_attributes( $handler_obj, $key, $value ) {
		if ( empty( $value ) ) {
			return array();
		}

		$custom_attributes        = array();
		$custom_attributes_keys   = array();
		$custom_attributes_values = array();
		foreach ( $value as $index => $attr ) {
			$custom_attributes_keys[]   = $index;
			$custom_attributes_values[] = $attr;
		}
		$custom_attributes['mosaml_custom_attr_keys']   = $custom_attributes_keys;
		$custom_attributes['mosaml_custom_attr_values'] = $custom_attributes_values;
		return $custom_attributes;
	}

	/**
	 * Format custom attributes display.
	 *
	 * @param object       $handler_obj The handler object.
	 * @param string       $key The key of the configuration.
	 * @param array|string $value The value to format.
	 * @return array The formatted value.
	 */
	public function format_custom_attributes_display( $handler_obj, $key, $value ) {
		$custom_attributes = $handler_obj->custom_attributes;

		$custom_attributes['mosaml_show_custom_attrs'] = $value;
		return $custom_attributes;
	}

	/**
	 * Validate that the role slug exists in WordPress. Falls back to the WP default role if not.
	 *
	 * @param object       $handler_obj The handler object.
	 * @param string       $key The key of the configuration.
	 * @param array|string $value The role slug to validate.
	 * @return string A valid WordPress role slug.
	 */
	public function validate_wp_role( $handler_obj, $key, $value ) {
		if ( empty( $value ) ) {
			return get_option( 'default_role', 'subscriber' );
		}

		$wp_roles = wp_roles();
		if ( ! isset( $wp_roles->roles[ $value ] ) ) {
			return get_option( 'default_role', 'subscriber' );
		}

		return $value;
	}

	/**
	 * Set the button attributes.
	 *
	 * @param object       $handler_obj The handler object.
	 * @param string       $key The key of the configuration.
	 * @param array|string $value The value to set the button attributes.
	 * @return array The button attributes.
	 */
	public function button_attributes( $handler_obj, $key, $value ) {
		$button_attributes = $handler_obj->sso_button_config;
		$key               = str_replace( 'sso_', '', $key );

		if ( 'button_theme' === $key ) {
			$key = 'button_type';
		}
		$button_attributes[ $key ] = ! empty( $value ) ? $value : ( isset( $button_attributes[ $key ] ) ? $button_attributes[ $key ] : '' );
		return $button_attributes;
	}

	/**
	 * Set the button font attributes.
	 *
	 * @param object       $handler_obj The handler object.
	 * @param string       $key The key of the configuration.
	 * @param array|string $value The value to set the button font attributes.
	 * @return array The button font attributes.
	 */
	public function button_font_attributes( $handler_obj, $key, $value ) {
		$button_font_attributes         = $handler_obj->sso_button_config;
		$key                            = str_replace( 'sso_button_', '', $key );
		$button_font_attributes[ $key ] = ! empty( $value ) ? $value : ( isset( $button_font_attributes[ $key ] ) ? $button_font_attributes[ $key ] : '' );
		return $button_font_attributes;
	}
}
