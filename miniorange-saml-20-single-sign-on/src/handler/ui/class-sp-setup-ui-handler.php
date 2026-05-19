<?php
/**
 * SP Setup UI Handler
 *
 * Renders the SP Setup admin tab and its sub-screens (IDP list, edit/add, upload metadata).
 *
 * @package miniorange-saml-20-single-sign-on/src/handler
 */

namespace MOSAML\SRC\Handler\UI;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\SRC\Interfaces\Tab_UI_Handler_Interface;
use MOSAML\SRC\Constant\Constants;
use MOSAML\SRC\Constant\Plugin_Files_Constants;
use MOSAML\SRC\Utils\Utility;
use MOSAML\SRC\Template\Idp_List_Table;
use MOSAML\SRC\Utils\Feature_Control;
use MOSAML\SRC\Utils\DB_Utils;

/**
 * SP Setup Template Handler.
 */
class SP_Setup_UI_Handler implements Tab_UI_Handler_Interface {

	/**
	 * Render the UI.
	 *
	 * @return void
	 */
	public function render_ui() {
		Utility::enforce_default_idp_state();
		$disabled                = Utility::disable_forms_if_no_idps_configured_bool();
		$disable_due_to_no_idp   = Utility::disable_forms_if_no_idps_configured();
		$disabled_due_to_license = Utility::mo_saml_get_disabled_attribute( ! Feature_Control::free_or_license_specific_feature_enabled() );

		$action             = Utility::sanitize_get_data( 'action' );
		$request_action     = Utility::sanitize_request_data( 'action' );
		$bulk_action_record = Utility::sanitize_request_data( 'bulk_action_record', true );
		$tab_name           = Utility::sanitize_get_data( 'tab' );
		if ( empty( $tab_name ) || ! array_key_exists( $tab_name, Constants::TABS ) ) {
			$tab_name = 'sp_setup';
		}
		$tab_handler            = Utility::get_handler_object( $tab_name . '_data', true, 'Admin' );
		$environment_id         = DB_Utils::get_environment_details( 'id', false );
		$current_environment_id = DB_Utils::get_environment_details( 'id', true );
		$is_current_environment = $environment_id === $current_environment_id;
		if ( ! empty( $request_action ) && ! empty( $bulk_action_record ) && array_key_exists( $request_action, Constants::IDP_BULK_ACTIONS ) ) {
			$default_idp_id = '';
			$idp_details    = $tab_handler->get_data(
				array(
					'environment_id' => $environment_id,
				),
				false
			);
			$idp_details    = array_filter(
				$idp_details,
				function ( $idp ) {
					return 'All IDPs' !== $idp->idp_name;
				}
			);
			foreach ( $idp_details as $idp ) {
				if ( $idp->default_idp ) {
					$default_idp_id = $idp->idp_id;
					break;
				}
			}
			$submit_button_text  = 'Confirm';
			$show_confirm_button = true;
			$idp_count           = is_countable( $idp_details ) ? count( $idp_details ) : 0;
			require_once Plugin_Files_Constants::TEMPLATE_BULK_ACTION_CONFIRMATION;
			return;
		}

		$idp_details     = $tab_handler->get_data( array( 'environment_id' => $environment_id ), false );
		$idp_details     = array_filter(
			$idp_details,
			function ( $idp ) {
				return 'All IDPs' !== $idp->idp_name;
			}
		);
		$is_editing_idp  = ( 'upload_metadata' === $action && ! empty( Utility::sanitize_get_data( 'idp' ) ) ) || ( 'edit' === $action && ! empty( Utility::sanitize_get_data( 'idp' ) ) );
		$disable_new_idp = Feature_Control::free_or_license_specific_feature_enabled() ? ( ! $is_editing_idp && ! empty( $idp_details ) && Feature_Control::is_feature_locked( 4 ) ? true : false ) : true;

		if ( 'upload_metadata' === $action ) {
			$action_url = add_query_arg(
				array(
					'page'   => 'mo_saml_settings',
					'tab'    => 'sp_setup',
					'action' => 'upload_metadata',
					'idp'    => Utility::sanitize_get_data( 'idp' ),
				),
				admin_url( 'admin.php' )
			);

			$data = $tab_handler->get_data(
				array(
					'environment_id' => $environment_id,
					'idp_id'         => Utility::sanitize_get_data( 'idp' ),
				)
			);
			require_once Plugin_Files_Constants::TEMPLATE_UPLOAD_IDP_METADATA;
		} elseif ( 'edit' === $action || 'add' === $action ) {
			if ( 'edit' === $action ) {
				$action_url = add_query_arg(
					array(
						'page'   => 'mo_saml_settings',
						'tab'    => 'sp_setup',
						'action' => 'edit',
						'idp'    => Utility::sanitize_get_data( 'idp' ),
					),
					admin_url( 'admin.php' )
				);
			} else {
				$action_url = add_query_arg(
					array(
						'page' => 'mo_saml_settings',
						'tab'  => 'sp_setup',
					),
					admin_url( 'admin.php' )
				);
			}
			$upload_metadata_url = add_query_arg(
				array(
					'page'   => 'mo_saml_settings',
					'tab'    => 'sp_setup',
					'action' => 'upload_metadata',
					'idp'    => Utility::sanitize_get_data( 'idp' ),
				),
				admin_url( 'admin.php' )
			);

			$cancel_url = add_query_arg(
				array(
					'page' => 'mo_saml_settings',
					'tab'  => 'sp_setup',
				),
				admin_url( 'admin.php' )
			);

			$idp_id_from_url = Utility::sanitize_get_data( 'idp' );

			$is_test_config_enabled = false;
			if ( 'edit' === $action && ! empty( $idp_id_from_url ) ) {
				$idp_data = $tab_handler->get_data(
					array(
						'idp_id'         => $idp_id_from_url,
						'environment_id' => $environment_id,
					)
				);

				if ( ! empty( $idp_data ) && isset( $idp_data->idp_id ) && ! empty( $idp_data->idp_id ) ) {
					$is_test_config_enabled = true;
				}
			}

			$test_url          = $is_test_config_enabled ? Utility::get_test_config_url( $idp_id_from_url ) : '#';
			$end_user_test_url = $is_test_config_enabled ? Utility::get_end_user_test_config_url( $idp_id_from_url ) : '';

			$data = $tab_handler->get_data(
				array(
					'idp_id'         => $idp_id_from_url,
					'environment_id' => $environment_id,
				)
			);

			$sync_tab_handler   = Utility::get_handler_object( 'metadata_sync_data', true, 'Admin' );
			$metadata_sync_data = $sync_tab_handler->get_data(
				array(
					'idp_id'         => Utility::sanitize_get_data( 'idp' ),
					'environment_id' => $environment_id,
				)
			);

			require_once Plugin_Files_Constants::TEMPLATE_SELECT_IDP_GRID;
			require_once Plugin_Files_Constants::TEMPLATE_IDP_MANUAL_CONFIG;
			$data             = $metadata_sync_data;
			$interval_options = Utility::get_sync_interval_options();
			require_once Plugin_Files_Constants::TEMPLATE_IDP_METADATA_SYNC;
		} else {
			$idp_list_table = new Idp_List_Table( $idp_details );
			$idp_list_table->prepare_items();
			require_once Plugin_Files_Constants::TEMPLATE_SP_SETUP;
		}
	}
}
