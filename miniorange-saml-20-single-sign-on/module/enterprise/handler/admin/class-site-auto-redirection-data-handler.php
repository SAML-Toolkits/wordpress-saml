<?php
/**
 * Enterprise Auto Redirection Data Handler.
 *
 * @package miniorange-saml-20-single-sign-on/module/enterprise/handler/admin
 */

namespace MOSAML\Module\Enterprise\Handler\Admin;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\Module\Premium\Handler\Admin\Site_Auto_Redirection_Data_Handler as Premium_Site_Auto_Redirection_Data_Handler;
use MOSAML\SRC\Interfaces\Form_Data_Handler_Interface;
use MOSAML\SRC\Utils\DB_Utils;
use MOSAML\SRC\Utils\Error_Success_Message;
use MOSAML\SRC\Utils\Utility;

/**
 * Enterprise Auto Redirection Data Handler.
 */
class Site_Auto_Redirection_Data_Handler extends Premium_Site_Auto_Redirection_Data_Handler implements Form_Data_Handler_Interface {

	/**
	 * Validate and save the data.
	 *
	 * @return void
	 */
	public function validate_and_save_data() {
		$this->site_auto_redirection_option = Utility::sanitize_post_data( 'mo_saml_auto_redirection_options' );
		$this->public_page_url              = Utility::sanitize_post_data( 'mo_saml_public_page_to_redirect' );
		if ( empty( $this->public_page_url ) ) {
			$this->public_page_url = site_url( '/' );
		}
		if ( Utility::is_3rd_party_url( $this->public_page_url ) ) {
			Error_Success_Message::show_admin_notice( '3rd party URL detected in Public Page URL. Please enter URL of the current site.' );
			return;
		}
		if ( filter_var( $this->public_page_url, FILTER_VALIDATE_URL ) === false ) {
			Error_Success_Message::show_admin_notice( 'Please enter a valid Public Page URL.' );
			return;
		}
		$this->public_page_url = rtrim( $this->public_page_url, '/' ) . '/';
		if ( 'public_page' === $this->site_auto_redirection_option && ! empty( $this->public_page_url ) ) {
			DB_Utils::insert_or_update(
				$this->get_table_name(),
				array(
					'option_name'  => 'public_page_url',
					'option_value' => $this->public_page_url,
					'subsite_id'   => Utility::get_subsite_id_for_environment(),
					'idp_id'       => DB_Utils::get_default_inserted_idp_details( 'id', DB_Utils::get_environment_details( 'id', false ) ),
				),
				array(
					'option_name' => 'public_page_url',
					'subsite_id'  => Utility::get_subsite_id_for_environment(),
					'idp_id'      => DB_Utils::get_default_inserted_idp_details( 'id', DB_Utils::get_environment_details( 'id', false ) ),
				)
			);
		}

		$this->is_site_auto_redirection_option_default = false;
		parent::validate_and_save_data();
	}

	/**
	 * Get the data.
	 *
	 * @param array $where The where clause to filter the data.
	 * @return object The data.
	 */
	public function get_data( $where = array() ) {
		$public_page_url_where = array_merge(
			array(
				'option_name' => 'public_page_url',
				'subsite_id'  => Utility::get_subsite_id_for_environment(),
			),
			$where
		);
		
		$record = DB_Utils::get_records(
			$this->get_table_name(),
			$public_page_url_where,
			true
		);
		if ( $record ) {
			$this->public_page_url = rtrim( $record->option_value, '/' ) . '/';
		}

		return parent::get_data( $where );
	}
}
