<?php
/**
 * SSO Button Data Handler - Premium Module
 *
 * Extends the standard SSO button data handler to provide premium module functionality.
 *
 * @package miniorange-saml-20-single-sign-on
 * @subpackage Module\Premium\Handler\Admin
 */

namespace MOSAML\Module\Premium\Handler\Admin;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\Module\Standard\Handler\Admin\SSO_Button_Data_Handler as Standard_SSO_Button_Data_Handler;
use MOSAML\SRC\Interfaces\Form_Data_Handler_Interface;
use MOSAML\SRC\Utils\Utility;

/**
 * SSO Button Data Handler.
 */
class SSO_Button_Data_Handler extends Standard_SSO_Button_Data_Handler implements Form_Data_Handler_Interface {

	/**
	 * Validate and save the SSO button configuration.
	 *
	 * @return void
	 */
	public function validate_and_save_data() {
		$this->sso_button_config = array(
			'button_type'     => Utility::sanitize_post_data( 'mo_saml_button_theme' ),
			'button_size'     => Utility::sanitize_post_data( 'mo_saml_button_size' ),
			'button_width'    => Utility::sanitize_post_data( 'mo_saml_button_width' ),
			'button_height'   => Utility::sanitize_post_data( 'mo_saml_button_height' ),
			'button_curve'    => Utility::sanitize_post_data( 'mo_saml_button_curve' ),
			'button_text'     => Utility::sanitize_post_data( 'mo_saml_button_text' ),
			'button_color'    => Utility::sanitize_post_data( 'mo_saml_button_color' ),
			'font_size'       => Utility::sanitize_post_data( 'mo_saml_font_size' ),
			'font_color'      => Utility::sanitize_post_data( 'mo_saml_font_color' ),
			'button_position' => Utility::sanitize_post_data( 'sso_button_login_form_position' ),
		);

		$use_button_as_shortcode_post  = Utility::sanitize_post_data( 'mo_saml_use_button_as_shortcode' );
		$this->use_button_as_shortcode = ( ! empty( $use_button_as_shortcode_post ) && 'checked' === $use_button_as_shortcode_post ) ? 'checked' : '';

		$use_button_as_widget_post  = Utility::sanitize_post_data( 'mo_saml_use_button_as_widget' );
		$this->use_button_as_widget = ( ! empty( $use_button_as_widget_post ) && 'checked' === $use_button_as_widget_post ) ? 'checked' : '';

		$this->sso_button_config['use_button_as_shortcode'] = $this->use_button_as_shortcode;
		$this->sso_button_config['use_button_as_widget']    = $this->use_button_as_widget;

		parent::validate_and_save_data();
	}

	/**
	 * Get the SSO button configuration.
	 *
	 * @param array $where The where clause to filter the data.
	 * @return object The data.
	 */
	public function get_data( $where = array() ) {
		return parent::get_data( $where );
	}
}
