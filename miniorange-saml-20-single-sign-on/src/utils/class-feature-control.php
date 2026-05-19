<?php
/**
 * Feature Control class
 *
 * @package MOSAML\SRC\Utils
 */

namespace MOSAML\SRC\Utils;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\SRC\Constant\Constants;
use MOSAML\SRC\Constant\Plugin_Files_Constants;

/**
 * Feature Control class
 *
 * @package MOSAML\SRC\Utils
 */
class Feature_Control {

	/**
	 * Check the plugin state.
	 *
	 * @return void
	 */
	public static function check_plugin_state() {
		$selected_environment_id = DB_Utils::get_environment_details( 'id', false );
		if ( self::check_is_license_verified() && Utility::mo_saml_is_no_idps_configured( $selected_environment_id ) ) {
			$active_tab = Utility::sanitize_get_data( 'tab' );
			if ( 'attribute_role_mapping' === $active_tab || 'sso_redirection_settings' === $active_tab || 'advanced_settings' === $active_tab ) {
				require_once Plugin_Files_Constants::NO_IDP_CONFIGURED_STRIP;
			}
		}

		if ( 1 === MOSAML_VERSION ) {
			return;
		}

		if ( ! Utility::handle_license_calls( 'is_account_verified', 'library', false ) ) {
			require_once Plugin_Files_Constants::LOGIN_REQUIRED_STRIP;
		} elseif ( ! self::check_is_license_verified() ) {
			require_once Plugin_Files_Constants::LICENSE_VERIFICATION_REQUIRED_STRIP;
		} elseif ( ! self::check_is_license_valid() ) {
			require_once Plugin_Files_Constants::LICENSE_EXPIRED_STRIP;
		} elseif ( Utility::mo_saml_is_idp_license_limit_exceeded( $selected_environment_id ) ) {
			require_once Plugin_Files_Constants::IDP_LICENSE_LIMIT_EXCEEDED_STRIP;
		}
	}

	/**
	 * Check if a feature is enabled
	 *
	 * @param int  $version The version of the feature.
	 * @param bool $check_expiry Whether to check license expiry.
	 * @return bool
	 */
	public static function is_feature_locked( $version, $check_expiry = true ) {
		return version_compare( MOSAML_VERSION, $version, '<' );
	}

	/**
	 * Check if a feature is disabled.
	 *
	 * @param int  $version The version of the feature.
	 * @param bool $idp_configuration_required Whether IDP configuration is required.
	 * @return bool True if the feature is disabled, false otherwise.
	 */
	public static function is_feature_disabled( $version, $idp_configuration_required = false ) {
		if ( self::is_feature_locked( $version ) ) {
			return true;
		}

		if ( 1 !== MOSAML_VERSION && ! self::check_is_license_verified() ) {
			return true;
		}

		$selected_environment_id = DB_Utils::get_environment_details( 'id', false );
		if ( $idp_configuration_required && Utility::mo_saml_is_no_idps_configured( $selected_environment_id ) ) {
			return true;
		}

		return false;
	}

	/**
	 * Check if a feature is enabled based on plugin version and license status
	 *
	 * Returns true for free version, true for paid version with valid license,
	 * and false for paid version with invalid license.
	 *
	 * @return bool True if free version or paid version with valid license, false otherwise.
	 */
	public static function free_or_license_specific_feature_enabled() {
		if ( 1 !== MOSAML_VERSION && ! self::check_is_license_valid() ) {
			return false;
		}

		return true;
	}

	/**
	 * Check if the license is verified.
	 *
	 * @return bool True if the license is verified, false otherwise.
	 */
	public static function check_is_license_verified() {

		if ( Utility::handle_license_calls( 'is_license_verified', 'library', false ) ) {
			return true;
		}
		return false;
	}

	/**
	 * Check if the license is valid.
	 *
	 * @return bool True if the license is valid, false otherwise.
	 */
	public static function check_is_license_valid() {

		if ( Utility::handle_license_calls( 'is_license_valid', 'library', false ) ) {
			return true;
		}
		return false;
	}

	/**
	 * Show the disabled feature info
	 *
	 * @param int  $version The version of the feature.
	 * @param bool $show_lock_icon Whether to show the lock icon.
	 * @return void
	 */
	private static function show_disabled_feature_info( $version, $show_lock_icon = true ) {
		if ( self::is_feature_locked( $version, false ) ) {
			?>
			<?php if ( $show_lock_icon ) { ?>
			<div class="mosaml-lock-wrapper mosaml-float-right">
				<svg class="mosaml-lock-img mosaml-float-right" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
					<path d="M13 14C13 13.4477 12.5523 13 12 13C11.4477 13 11 13.4477 11 14V16C11 16.5523 11.4477 17 12 17C12.5523 17 13 16.5523 13 16V14Z" fill="currentColor"/>
					<path fill-rule="evenodd" clip-rule="evenodd" d="M7 8.12037C5.3161 8.53217 4 9.95979 4 11.7692V17.3077C4 19.973 6.31545 22 9 22H15C17.6846 22 20 19.973 20 17.3077V11.7692C20 9.95979 18.6839 8.53217 17 8.12037V7C17 4.23858 14.7614 2 12 2C9.23858 2 7 4.23858 7 7V8.12037ZM15 7V8H9V7C9 6.64936 9.06015 6.31278 9.17071 6C9.58254 4.83481 10.6938 4 12 4C13.3062 4 14.4175 4.83481 14.8293 6C14.9398 6.31278 15 6.64936 15 7ZM6 11.7692C6 10.866 6.81856 10 8 10H16C17.1814 10 18 10.866 18 11.7692V17.3077C18 18.7208 16.7337 20 15 20H9C7.26627 20 6 18.7208 6 17.3077V11.7692Z" fill="currentColor"/>
				</svg>
				<?php self::show_tooltip_for_disabled_feature( $version ); ?>
			</div>
			<?php } ?>
			<?php
		}
	}

	/**
	 * Show tooltip for disabled feature
	 *
	 * @param int $version The version of the feature.
	 * @return void
	 */
	public static function show_tooltip_for_disabled_feature( $version ) {
		if ( self::is_feature_locked( $version, false ) ) {
			?>
			<div class="mosaml-lock-tooltip">
				<span class="mosaml-lock-tooltiptext">
					This feature is not available in the current version of the plugin. Please upgrade to the <i><?php echo esc_html( Constants::VERSION_HIERARCHY[ $version ] ); ?> or higher version</i> to use this feature. <a href="<?php echo esc_url( Constants::PRICING_PAGE_URL ); ?>" target="_blank">Click here</a> to upgrade.
				</span>
			</div>
			<?php
		}
	}

	/**
	 * Get the disabled class for feature locking
	 *
	 * @param int $version The version of the feature.
	 * @return string The disabled class if the feature is disabled, empty string otherwise.
	 */
	public static function get_disabled_attribute( $version ) {
		return self::is_feature_locked( $version, false ) ? 'disabled' : '';
	}

	/**
	 * Start feature lock container
	 *
	 * @param int  $version The version of the feature.
	 * @param bool $show_lock_icon Whether to show the lock icon.
	 * @return void
	 */
	public static function start_feature_lock_container( $version, $show_lock_icon = true ) {
		if ( self::is_feature_locked( $version, false ) ) {
			?>
			<div class="mosaml-feature-lock-container mosaml-justify-content-center">
				<fieldset disabled>
				<?php
				self::show_disabled_feature_info( $version, $show_lock_icon );
				?>
			<?php
		}
	}

	/**
	 * End feature lock container
	 *
	 * @param int $version The version of the feature.
	 * @return void
	 */
	public static function end_feature_lock_container( $version ) {
		if ( self::is_feature_locked( $version, false ) ) {
			?>
				</fieldset>
			</div>
			<?php
		}
	}

	/**
	 * Get the feature lock icon
	 *
	 * @param int $version The version of the feature.
	 * @return void
	 */
	public static function get_feature_lock_icon( $version ) {
		if ( self::is_feature_locked( $version, false ) ) {
			?>
				<svg style="width: 1.5rem; height: 1.3rem; margin-bottom: -0.3rem;" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
					<path d="M13 14C13 13.4477 12.5523 13 12 13C11.4477 13 11 13.4477 11 14V16C11 16.5523 11.4477 17 12 17C12.5523 17 13 16.5523 13 16V14Z" fill="currentColor"/>
					<path fill-rule="evenodd" clip-rule="evenodd" d="M7 8.12037C5.3161 8.53217 4 9.95979 4 11.7692V17.3077C4 19.973 6.31545 22 9 22H15C17.6846 22 20 19.973 20 17.3077V11.7692C20 9.95979 18.6839 8.53217 17 8.12037V7C17 4.23858 14.7614 2 12 2C9.23858 2 7 4.23858 7 7V8.12037ZM15 7V8H9V7C9 6.64936 9.06015 6.31278 9.17071 6C9.58254 4.83481 10.6938 4 12 4C13.3062 4 14.4175 4.83481 14.8293 6C14.9398 6.31278 15 6.64936 15 7ZM6 11.7692C6 10.866 6.81856 10 8 10H16C17.1814 10 18 10.866 18 11.7692V17.3077C18 18.7208 16.7337 20 15 20H9C7.26627 20 6 18.7208 6 17.3077V11.7692Z" fill="currentColor"/>
				</svg>
			<?php
		}
	}
}
