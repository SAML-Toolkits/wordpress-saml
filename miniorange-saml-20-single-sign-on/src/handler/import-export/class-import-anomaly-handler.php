<?php
/**
 * Import Anomaly Handler.
 *
 * @package MOSAML\SRC\Handler\Import_Export
 */

namespace MOSAML\SRC\Handler\Import_Export;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\Traits\Instance;

/**
 * Import Anomaly Handler.
 */
class Import_Anomaly_Handler {

	use Instance;

	/**
	 * Set the default IDP.
	 *
	 * @param string $value The value.
	 * @param array  $handler_instances The handler instances.
	 * @return void
	 */
	public function set_default_idp( $value, $handler_instances = array() ) {
		if ( isset( $handler_instances[ $value ] ) && ! empty( $handler_instances[ $value ]['SP_Setup_Data'] ) ) {
			$handler_obj              = $handler_instances[ $value ]['SP_Setup_Data'];
			$handler_obj->default_idp = true;
			$handler_obj->status      = 'active';
		}
	}

	/**
	 * Set the IDP fields.
	 *
	 * @param string $value The value.
	 * @param object $handler_obj The handler object.
	 * @return void
	 */
	public function set_idp_fields( $value, $handler_obj = null ) {
		$handler_obj->idp_id             = $value;
		$handler_obj->default_idp        = true;
		$handler_obj->status             = 'active';
		$handler_obj->name_id_format     = ! empty( $handler_obj->name_id_format ) ? $handler_obj->name_id_format : 'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified';
		$handler_obj->character_encoding = '';
	}

	/**
	 * Set the custom certificate.
	 *
	 * @param string $value The value.
	 * @param object $handler_obj The handler object.
	 * @return void
	 */
	public function set_custom_certificate( $value, $handler_obj = null ) {
		$handler_obj->public_key            = $value['Custom_Public_Certificate'];
		$handler_obj->private_key           = $value['Custom_Private_Certificate'];
		$handler_obj->is_custom_certificate = 1;
	}

	/**
	 * Set the default role existing.
	 *
	 * @param string $value The value.
	 * @param object $handler_obj The handler object.
	 * @return void
	 */
	public function set_default_role_existing( $value, $handler_obj = null ) {
		$handler_obj->default_role_existing = $value;
	}

	/**
	 * Save the WP widget config.
	 *
	 * @param string $value The value.
	 * @param object $handler_obj The handler object.
	 * @return void
	 */
	public function save_wp_widget_config( $value, $handler_obj = null ) {
		update_option( 'widget_mosaml_login_widget', $value );
	}

	/**
	 * Handle the relay states.
	 *
	 * @param string $value The value.
	 * @param object $handler_obj The handler object.
	 * @return void
	 */
	public function handle_relay_states( $value, $handler_obj = null ) {
		if ( empty( $handler_obj->allow_third_party_relay_state ) || 'checked' !== $handler_obj->allow_third_party_relay_state ) {
			$site_url = rtrim( get_site_url(), '/' );
			if ( ! empty( $handler_obj->login_relay_state ) ) {
				$handler_obj->login_relay_state = $site_url . $handler_obj->login_relay_state;
			}
			if ( ! empty( $handler_obj->logout_relay_state ) ) {
				$handler_obj->logout_relay_state = $site_url . $handler_obj->logout_relay_state;
			}
		}
	}

	/**
	 * Set the enable site auto redirect.
	 *
	 * @param string $value The value.
	 * @param object $handler_obj The handler object.
	 * @return void
	 */
	public function set_enable_site_auto_redirect( $value, $handler_obj = null ) {
		$handler_obj->enable_site_auto_redirect = ! empty( $value ) && true === (bool) $value ? 'checked' : '';
	}

	/**
	 * Enable metadata sync.
	 *
	 * @param string $value The value.
	 * @param object $handler_obj The handler object.
	 * @return void
	 */
	public function enable_metadata_sync( $value, $handler_obj = null ) {
		$handler_obj->sync_metadata = ! empty( $value ) ? 'checked' : '';
	}

	/**
	 * Handle the none role.
	 *
	 * @param string $value The value.
	 * @param object $handler_obj The handler object.
	 * @return void
	 */
	public function handle_none_role( $value, $handler_obj = null ) {
		if ( true !== (bool) $value ) {
			return;
		}

		$handler_obj->create_new_user       = 'checked';
		$handler_obj->update_existing_user  = 'checked';
		$handler_obj->default_role_new      = 'none';
		$handler_obj->default_role_existing = 'none';
	}

	/**
	 * Handle the default role.
	 *
	 * @param string $value The value.
	 * @param object $handler_obj The handler object.
	 * @return void
	 */
	public function handle_default_role( $value, $handler_obj = null ) {
		if ( true !== (bool) $value ) {
			return;
		}

		$handler_obj->create_new_user      = 'checked';
		$handler_obj->update_existing_user = 'checked';
	}
}
