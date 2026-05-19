<?php
/**
 * Standard Auto Redirection Data Handler.
 *
 * @package miniorange-saml-20-single-sign-on/module/standard/handler/admin
 */

namespace MOSAML\Module\Standard\Handler\Admin;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\Module\Base\Handler\Admin\Site_Auto_Redirection_Data_Handler as Base_Site_Auto_Redirection_Data_Handler;
use MOSAML\SRC\Interfaces\Form_Data_Handler_Interface;
use MOSAML\SRC\Utils\DB_Utils;
use MOSAML\SRC\Utils\Error_Success_Message;
use MOSAML\SRC\Utils\Utility;

/**
 * Standard Auto Redirection Data Handler.
 */
class Site_Auto_Redirection_Data_Handler extends Base_Site_Auto_Redirection_Data_Handler implements Form_Data_Handler_Interface {

	/**
	 * Validate and save the data.
	 *
	 * @return void
	 */
	public function validate_and_save_data() {
		$idp_id = DB_Utils::get_default_inserted_idp_details( 'id', DB_Utils::get_environment_details( 'id', false ) );

		$this->enable_site_auto_redirect = Utility::sanitize_post_data( 'mo_saml_enable_auto_redirect' );
		DB_Utils::insert_or_update(
			$this->get_table_name(),
			array(
				'option_name'  => 'enable_site_auto_redirect',
				'option_value' => $this->enable_site_auto_redirect,
				'subsite_id'   => Utility::get_subsite_id_for_environment(),
				'idp_id'       => $idp_id,
			),
			array(
				'option_name' => 'enable_site_auto_redirect',
				'subsite_id'  => Utility::get_subsite_id_for_environment(),
				'idp_id'      => $idp_id,
			)
		);
		if ( 'checked' !== $this->enable_site_auto_redirect ) {
			Error_Success_Message::show_admin_notice( 'Auto redirection from site options saved successfully.', 'SUCCESS' );
			return;
		}

		$site_auto_redirection_option       = 'public_page' !== Utility::sanitize_post_data( 'mo_saml_auto_redirection_options' ) && 'wp_login' !== Utility::sanitize_post_data( 'mo_saml_auto_redirection_options' ) ? Utility::sanitize_post_data( 'mo_saml_auto_redirection_options' ) : 'default_idp';
		$this->site_auto_redirection_option = ! $this->is_site_auto_redirection_option_default ? $this->site_auto_redirection_option : $site_auto_redirection_option;
		if ( ! $this->site_auto_redirection_option ) {
			$this->site_auto_redirection_option = 'default_idp';
		}
		DB_Utils::insert_or_update(
			$this->get_table_name(),
			array(
				'option_name'  => 'site_auto_redirection_option',
				'option_value' => $this->site_auto_redirection_option,
				'subsite_id'   => Utility::get_subsite_id_for_environment(),
				'idp_id'       => $idp_id,
			),
			array(
				'option_name' => 'site_auto_redirection_option',
				'subsite_id'  => Utility::get_subsite_id_for_environment(),
				'idp_id'      => $idp_id,
			)
		);
		Error_Success_Message::show_admin_notice( 'Auto redirection from site options saved successfully.', 'SUCCESS' );
	}

	/**
	 * Get the data.
	 *
	 * @param array $where The where clause to filter the data.
	 * @return object The data.
	 */
	public function get_data( $where = array() ) {
		$site_auto_redirection_where = array_merge(
			array(
				'option_name' => 'enable_site_auto_redirect',
				'subsite_id'  => Utility::get_subsite_id_for_environment(),
			),
			$where
		);

		$record = DB_Utils::get_records(
			$this->get_table_name(),
			$site_auto_redirection_where,
			true
		);
		if ( $record ) {
			$this->enable_site_auto_redirect = $record->option_value;
		}

		$site_auto_redirection_option_where = array_merge(
			array(
				'option_name' => 'site_auto_redirection_option',
				'subsite_id'  => Utility::get_subsite_id_for_environment(),
			),
			$where
		);

		$record = DB_Utils::get_records(
			$this->get_table_name(),
			$site_auto_redirection_option_where,
			true
		);
		if ( $record ) {
			$this->site_auto_redirection_option = $record->option_value;
		}

		return parent::get_data( $where );
	}
}
