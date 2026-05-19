<?php
/**
 * Show Custom Attribute Handler.
 *
 * This file contains the Base Show_Custom_Attribute_Handler class that handles the display of custom attributes.
 *
 * @package MOSAML
 * @subpackage Base\Handler\Config
 * @since 1.0.0
 */

namespace MOSAML\Module\Premium\Handler\Config;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\SRC\Utils\Utility;
use MOSAML\Module\Standard\Handler\Config\Show_Custom_Attributes_Handler as Standard_Show_Custom_Attributes_Handler;

/**
 * Show Custom Attribute Handler.
 *
 * This class handles the display of custom attributes.
 *
 * @since 1.0.0
 */
class Show_Custom_Attributes_Handler extends Standard_Show_Custom_Attributes_Handler {

	/**
	 * Add a column in the WordPress Users menu for custom attributes
	 *
	 * @param array $columns the columnns to be displayed in the users list.
	 */
	public static function mo_saml_custom_attr_column( $columns ) {
		$custom_attributes = Utility::get_handler_object( 'attribute_mapping_data', true, 'admin' )->get_data()->custom_attributes;
		foreach ( $custom_attributes as $key => $value ) {
			if ( ! empty( $value['name'] ) ) {
				if ( ! empty( $value['display'] ) ) {
					$columns[ $value['name'] ] = $value['name'];
				}
			}
		}
		return $columns;
	}

	/**
	 * Populate the User's custom attribute column's field
	 *
	 * @param string $output The output to be displayed for the columns speficied.
	 * @param string $column_name The column name where output to be displayed.
	 * @param int    $user_id The user for which output to be displayed.
	 */
	public static function mo_saml_attr_column_content( $output, $column_name, $user_id ) {
		$custom_attributes = Utility::get_handler_object( 'attribute_mapping_data', true, 'admin' )->get_data()->custom_attributes;
		if ( ! empty( $custom_attributes ) && is_array( $custom_attributes ) ) {
			foreach ( $custom_attributes as $idp => $values ) {
				if ( ! empty( $values ) ) {
					if ( ! empty( $values['display'] ) && $values['name'] === $column_name ) {
						$content = get_user_meta( $user_id, $column_name, false );
						if ( ! empty( $content ) && is_array( $content ) && isset( $content[0] ) ) {
							if ( ! is_array( $content[0] ) ) {
								return esc_html( $content[0] );
							} else {
								$result = '';
								foreach ( $content[0] as $attr_value ) {
									$result = $result . $attr_value;
									if ( next( $content[0] ) ) {
										$result = $result . ' | ';
									}
								}
								$result = map_deep( wp_unslash( $result ), 'esc_html' );
								return $result;
							}
						}
					}
				}
			}
		}
		return $output;
	}
}
