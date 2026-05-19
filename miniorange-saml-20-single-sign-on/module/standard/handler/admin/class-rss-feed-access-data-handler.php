<?php
/**
 * Standard Enable RSS Access Data Handler.
 *
 * @package miniorange-saml-20-single-sign-on/module/standard/handler/admin
 */

namespace MOSAML\Module\Standard\Handler\Admin;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\Module\Base\Handler\Admin\RSS_Feed_Access_Data_Handler as Base_Enable_RSS_Access_Data_Handler;
use MOSAML\SRC\Interfaces\Form_Data_Handler_Interface;
use MOSAML\SRC\Utils\DB_Utils;
use MOSAML\SRC\Utils\Error_Success_Message;
use MOSAML\SRC\Utils\Utility;

/**
 * Standard Enable RSS Access Data Handler.
 */
class RSS_Feed_Access_Data_Handler extends Base_Enable_RSS_Access_Data_Handler implements Form_Data_Handler_Interface {

	/**
	 * Validate and save the data.
	 *
	 * @return void
	 */
	public function validate_and_save_data() {
		$this->enable_rss_feed_access = Utility::sanitize_post_data( 'mo_saml_enable_rss_access' );
		$query_result                 = DB_Utils::insert_or_update(
			$this->get_table_name(),
			array(
				'option_name'  => 'enable_rss_feed_access',
				'option_value' => $this->enable_rss_feed_access,
				'subsite_id'   => Utility::get_subsite_id_for_environment(),
				'idp_id'       => DB_Utils::get_default_inserted_idp_details( 'id', DB_Utils::get_environment_details( 'id', false ) ),
			),
			array(
				'option_name' => 'enable_rss_feed_access',
				'subsite_id'  => Utility::get_subsite_id_for_environment(),
				'idp_id'      => DB_Utils::get_default_inserted_idp_details( 'id', DB_Utils::get_environment_details( 'id', false ) ),
			)
		);
		if ( $query_result ) {
			Error_Success_Message::show_admin_notice( 'RSS Feed option updated.', 'SUCCESS' );
		}
	}

	/**
	 * Get the data.
	 *
	 * @param array $where The where clause to filter the data.
	 * @return object The data.
	 */
	public function get_data( $where = array() ) {
		$where  = array_merge(
			array(
				'option_name' => 'enable_rss_feed_access',
				'subsite_id'  => Utility::get_subsite_id_for_environment(),
			),
			$where
		);
		$record = DB_Utils::get_records(
			$this->get_table_name(),
			$where,
			true
		);
		if ( $record ) {
			$this->enable_rss_feed_access = $record->option_value;
		}
		return parent::get_data( $where );
	}
}
