<?php
/**
 * Widget Data Handler - Standard Module
 *
 * Extends the base widget data handler to provide standard module functionality.
 *
 * PHP Compatibility: 5.6+
 *
 * @package miniorange-saml-20-single-sign-on
 * @subpackage Module\Standard\Handler\Admin
 */

namespace MOSAML\Module\Standard\Handler\Admin;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\Module\Base\Handler\Admin\Shortcode_Widget_Data_Handler as Base_Shortcode_Widget_Data_Handler;
use MOSAML\SRC\Interfaces\Form_Data_Handler_Interface;
use MOSAML\SRC\Utils\DB_Utils;
use MOSAML\SRC\Utils\Error_Success_Message;
use MOSAML\SRC\Utils\Utility;

/**
 * Widget Data Handler.
 */
class Shortcode_Widget_Data_Handler extends Base_Shortcode_Widget_Data_Handler implements Form_Data_Handler_Interface {

	/**
	 * Validate and save the widget configuration.
	 *
	 * @return void
	 */
	public function validate_and_save_data() {
		$this->widget_config = array(
			'custom_login_text'    => Utility::sanitize_post_data( 'mo_saml_custom_login_text' ),
			'custom_greeting_text' => Utility::sanitize_post_data( 'mo_saml_custom_greeting_text' ),
			'custom_logout_text'   => Utility::sanitize_post_data( 'mo_saml_custom_logout_text' ),
			'greeting_name'        => Utility::sanitize_post_data( 'mo_saml_greeting_name' ),
		);
		$idp_id              = Utility::sanitize_post_data( 'sso_link_idp' );
		$table_data          = array(
			'option_name'  => 'widget_config',
			'option_value' => $this->widget_config,
			'idp_id'       => $idp_id,
			'subsite_id'   => Utility::get_subsite_id_for_environment(),
		);
		$query_result        = DB_Utils::insert_or_update(
			$this->get_table_name(),
			$table_data,
			array(
				'option_name' => 'widget_config',
				'idp_id'      => $idp_id,
				'subsite_id'  => Utility::get_subsite_id_for_environment(),
			)
		);
		if ( $query_result ) {
			Error_Success_Message::show_admin_notice( 'Custom Widget details saved successfully.', 'SUCCESS' );
		}
	}

	/**
	 * Get the widget configuration.
	 *
	 * @param array $where The where clause to filter the data.
	 * @return object The data.
	 */
	public function get_data( $where = array() ) {
		if ( Utility::is_legacy_data_fallback_required() ) {
			return apply_filters( 'mosaml_legacy_data_fallback_object', $this, $where );
		}
		$where['option_name'] = 'widget_config';
		$where['subsite_id']  = Utility::get_subsite_id_for_environment();
		$result               = DB_Utils::get_records( $this->get_table_name(), $where, true );
		if ( ! empty( $result ) && ! empty( $result->option_value ) ) {
			$this->widget_config = maybe_unserialize( $result->option_value );
		} else {
			$this->widget_config = array();
		}
		return $this;
	}
}
