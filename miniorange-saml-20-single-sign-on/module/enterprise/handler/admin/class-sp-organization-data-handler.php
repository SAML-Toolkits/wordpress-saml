<?php
/**
 * This file includes the save and get function for SP Organization as per the enterprise plan.
 *
 * @package MOSAML\Module\Enterprise\Handler\Admin
 */

namespace MOSAML\Module\Enterprise\Handler\Admin;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\Module\Premium\Handler\Admin\SP_Organization_Data_Handler as Premium_SP_Organization_Data_Handler;
use MOSAML\SRC\Interfaces\Form_Data_Handler_Interface;
use MOSAML\SRC\Utils\DB_Utils;
use MOSAML\SRC\Utils\Error_Success_Message;
use MOSAML\SRC\Utils\Utility;

/**
 * SP Organization Data Handler.
 */
class SP_Organization_Data_Handler extends Premium_SP_Organization_Data_Handler implements Form_Data_Handler_Interface {

	/**
	 * Validate and save the sp organization data.
	 *
	 * @return void
	 */
	public function validate_and_save_data() {

		$this->organization_name         = Utility::sanitize_post_data( 'mo_saml_org_name' );
		$this->organization_display_name = Utility::sanitize_post_data( 'mo_saml_org_display_name' );
		$this->organization_url          = Utility::sanitize_post_data( 'mo_saml_org_url', false, 'esc_url_raw' );
		$this->technical_person_name     = Utility::sanitize_post_data( 'mo_saml_tech_name' );
		$this->technical_person_email    = Utility::sanitize_post_data( 'mo_saml_tech_email', false, 'sanitize_email' );
		$this->support_person_name       = Utility::sanitize_post_data( 'mo_saml_support_name' );
		$this->support_person_email      = Utility::sanitize_post_data( 'mo_saml_support_email', false, 'sanitize_email' );
		if ( ! empty( $this->organization_name ) && ! empty( $this->organization_url ) && ! empty( $this->organization_display_name ) && ! empty( $this->support_person_name ) && ! empty( $this->support_person_email ) && ! empty( $this->support_person_name ) && ! empty( $this->support_person_email ) ) {

			if ( ! is_email( $this->support_person_email ) || ! is_email( $this->technical_person_email ) ) {
				Error_Success_Message::show_admin_notice( 'Please enter valid email.' );
				return;
			} elseif ( ! filter_var( $this->organization_url, FILTER_VALIDATE_URL ) ) {
				Error_Success_Message::show_admin_notice( 'Please enter valid url.' );
				return;
			}

			$insert_data                   = get_object_vars( $this );
			$insert_data['environment_id'] = ! empty( $insert_data['environment_id'] ) ? $insert_data['environment_id'] : DB_Utils::get_environment_details( 'id', false );

			$where = array(
				'environment_id' => $insert_data['environment_id'],
			);

			$query_result = DB_Utils::insert_or_update( $this->get_table_name(), $insert_data, $where );
			if ( $query_result ) {
				$success_msg  = 'Organization details updated successfully. You can view the updated details by clicking here. ';
				$success_msg .= Error_Success_Message::get_sp_metadata_view_link_for_notice();
				Error_Success_Message::show_admin_notice( $success_msg, 'SUCCESS' );
			}

			return $query_result;
		} else {
			Error_Success_Message::show_admin_notice( 'All fields are required.' );
			return;
		}
	}

	/**
	 * Get the sp organization data.
	 *
	 * @param array $where The where clause to filter the data.
	 * @return object The data.
	 */
	public function get_data( $where = array() ) {

		$where = array_merge( $where, array( 'environment_id' => DB_Utils::get_environment_details( 'id', false ) ) );

		$record = DB_Utils::get_records( $this->get_table_name(), $where, true );
		if ( $record ) {
			$values_to_be_set = (array) $record;
			foreach ( $values_to_be_set as $column => $value ) {
				if ( property_exists( $this, $column ) && null !== $value && '' !== $value ) {
					$this->$column = $value;
				}
			}
		}

		return $this;
	}
}
