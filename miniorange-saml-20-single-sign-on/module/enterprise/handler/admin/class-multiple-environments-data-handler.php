<?php
/**
 * Multiple Environments Data Handler - Enterprise Module
 *
 * Handles data operations for multiple environments configuration in the enterprise module.
 *
 * @package miniorange-saml-20-single-sign-on
 * @subpackage Module\Enterprise\Handler\Admin
 */

namespace MOSAML\Module\Enterprise\Handler\Admin;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\Module\Premium\Handler\Admin\Multiple_Environments_Data_Handler as Premium_Multiple_Environments_Data_Handler;
use MOSAML\SRC\Interfaces\Form_Data_Handler_Interface;
use MOSAML\SRC\Utils\Utility;
use MOSAML\SRC\Utils\DB_Utils;
use MOSAML\SRC\Constant\Constants;
use MOSAML\SRC\Utils\Error_Success_Message;

/**
 * Multiple Environments Data Handler.
 */
class Multiple_Environments_Data_Handler extends Premium_Multiple_Environments_Data_Handler implements Form_Data_Handler_Interface {

	/**
	 * Validate and save the multiple environments configuration.
	 *
	 * @return void
	 */
	public function validate_and_save_data() {
		if ( 'checked' !== get_option( Constants::ENABLE_MULTIPLE_ENVIRONMENTS_OPTION_NAME ) ) {
			return;
		}

		$submit_type = Utility::sanitize_post_data( 'submit_type' );

		$this->id = Utility::sanitize_post_data( 'environment_id' );
		if ( 'edit' === $submit_type ) {
			$this->environment_name = Utility::sanitize_post_data( 'environment_name' );
			$this->environment_url  = Utility::sanitize_post_data( 'environment_url' );

			if ( DB_Utils::get_environment_details( 'id' ) === $this->id && DB_Utils::get_environment_details( 'environment_url' ) !== $this->environment_url ) {
				Error_Success_Message::show_admin_notice( 'You cannot change the URL of the currently selected environment.', 'ERROR' );
				return;
			}

			DB_Utils::insert_or_update(
				$this->get_table_name(),
				get_object_vars( $this ),
				array(
					'id' => $this->id,
				),
			);
			Error_Success_Message::show_admin_notice( 'Environment updated successfully.', 'SUCCESS' );
		} elseif ( 'delete' === $submit_type ) {
			if ( DB_Utils::get_environment_details( 'id', false ) === $this->id ) {
				Error_Success_Message::show_admin_notice( 'You have selected this environment in the plugin, hence you cannot delete it. Please switch to a different environment first.', 'ERROR' );
				return;
			}
			DB_Utils::delete_records(
				$this->get_table_name(),
				array(
					'id' => $this->id,
				)
			);
			Error_Success_Message::show_admin_notice( 'Environment deleted successfully.', 'SUCCESS' );
		} elseif ( 'add' === $submit_type ) {
			$this->environment_name = Utility::sanitize_post_data( 'environment_name' );
			$this->environment_url  = Utility::sanitize_post_data( 'environment_url' );

			$existing_environment_check = DB_Utils::get_records(
				$this->get_table_name(),
				array(
					'environment_name' => $this->environment_name,
					'environment_url'  => $this->environment_url,
				),
				true,
				'OR',
			);
			if ( $existing_environment_check ) {
				Error_Success_Message::show_admin_notice( 'An environment with the same name or URL already exists.', 'ERROR' );
				return;
			}

			$result = DB_Utils::insert_or_update(
				$this->get_table_name(),
				get_object_vars( $this ),
				array(
					'environment_name' => $this->environment_name,
					'environment_url'  => $this->environment_url,
					'selected'         => false,
				),
				'AND',
				true
			);

			if ( $result ) {
				DB_Utils::initialize_sp_metadata_table( $result, $this->environment_url );
				DB_Utils::initialize_idp_details_table( $result );
				DB_Utils::initialize_subsites_table( $result, Constants::DEFAULT_BLOG_ID, $this->environment_url );
				DB_Utils::initialize_attribute_mapping_table( $result );
				Error_Success_Message::show_admin_notice( 'Environment added successfully.', 'SUCCESS' );
			}
		}
	}

	/**
	 * Change the environment.
	 *
	 * @return void
	 */
	public function change_environment() {
		$environment_name = Utility::sanitize_post_data( 'environment' );
		if ( empty( $environment_name ) ) {
			return;
		}

		$environment_exists = DB_Utils::get_records(
			$this->get_table_name(),
			array( 'environment_name' => $environment_name ),
			true
		);

		if ( ! $environment_exists ) {
			return;
		}

		$selected_environment = DB_Utils::get_records( $this->get_table_name(), array( 'selected' => true ) );
		if ( $selected_environment ) {
			foreach ( $selected_environment as $environment ) {
				// Unselect currently selected environment, if any.
				DB_Utils::insert_or_update( $this->get_table_name(), array( 'selected' => false ), array( 'id' => $environment->id ) );
			}
		}

		// Select the requested environment.
		DB_Utils::insert_or_update( $this->get_table_name(), array( 'selected' => true ), array( 'environment_name' => $environment_name ) );
	}
}
