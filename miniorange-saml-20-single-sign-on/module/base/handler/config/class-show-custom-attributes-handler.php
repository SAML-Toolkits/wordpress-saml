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

namespace MOSAML\Module\Base\Handler\Config;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Show Custom Attribute Handler.
 *
 * This class handles the display of custom attributes.
 *
 * @since 1.0.0
 */
class Show_Custom_Attributes_Handler {

	/**
	 * Add a column in the WordPress Users menu for custom attributes
	 *
	 * @param array $columns the columnns to be displayed in the users list.
	 */
	public static function mo_saml_custom_attr_column( $columns ) {
		return $columns;
	}

	/**
	 * Populate the User's custom attribute column's field
	 *
	 * @param string $output The output to be displayed for the columns speficied.
	 * @param string $column_name The column name where output to be displayed.
	 * @param int    $user_id The user for which output to be displayed.
	 */
	public static function mo_saml_attr_column_content( $output, $column_name, $user_id ) { // phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter.FoundAfterLastUsed
		return $output;
	}
}
