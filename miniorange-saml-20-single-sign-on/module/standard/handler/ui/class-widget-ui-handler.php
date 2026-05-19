<?php
/**
 * Widget UI Handler - Standard Module
 *
 * Extends base widget handler to add customization features.
 *
 * @package miniorange-saml-20-single-sign-on
 * @subpackage Module\Standard\Handler\UI
 */

namespace MOSAML\Module\Standard\Handler\UI;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\Module\Base\Handler\UI\Widget_UI_Handler as Base_Widget_UI_Handler;

/**
 * Widget UI Handler - Standard Module.
 * Adds widget customization features to base functionality.
 */
class Widget_UI_Handler extends Base_Widget_UI_Handler {

	/**
	 * Get login text for widget.
	 * Standard module supports custom text.
	 *
	 * @param object $shortcode_widget_data Widget data object.
	 * @param object $idp IDP object.
	 * @return string
	 */
	protected function get_login_text( $shortcode_widget_data, $idp ) {
		return ! empty( $shortcode_widget_data->widget_config['custom_login_text'] )
			? $shortcode_widget_data->widget_config['custom_login_text']
			: 'Login with ' . $idp->idp_name;
	}

	/**
	 * Get greeting text for widget.
	 * Standard module supports custom text.
	 *
	 * @param object $shortcode_widget_data Widget data object.
	 * @return string
	 */
	protected function get_greeting_text( $shortcode_widget_data ) {
		return ! empty( $shortcode_widget_data->widget_config['custom_greeting_text'] )
			? $shortcode_widget_data->widget_config['custom_greeting_text']
			: 'Hello,';
	}

	/**
	 * Get logout text for widget.
	 * Standard module supports custom text.
	 *
	 * @param object $shortcode_widget_data Widget data object.
	 * @return string
	 */
	protected function get_logout_text( $shortcode_widget_data ) {
		return ! empty( $shortcode_widget_data->widget_config['custom_logout_text'] )
			? $shortcode_widget_data->widget_config['custom_logout_text']
			: 'Logout';
	}
}
