<?php
/**
 * This file displays all the add-ons listed in the plugin.
 *
 * @package    miniOrange
 * @author     miniOrange Security Software Pvt. Ltd.
 */

namespace MOSAML\LicenseLibrary\Views;

use MOSAML\LicenseLibrary\Views\Mo_Options_Addons;
use MOSAML\LicenseLibrary\Classes\Mo_License_Constants;
use MOSAML\LicenseLibrary\Classes\Mo_License_API_Client;
use MOSAML\LicenseLibrary\Mo_License_Config;
use MOSAML\LicenseLibrary\Utils\Mo_License_Actions_Utility;
use MOSAML\LicenseLibrary\Mo_License_Service;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}
/**
 * Mo_License_Addons_Views Class contains functions to display the addons tab related
 * to plugin's licenses.
 */
class Mo_License_Addons_Views {

	/**
	 * The function contains details for all the add-ons.
	 *
	 * @return void
	 */
	public static function show_addons_page() {
		$disabled = false;

		$is_logged_in = Mo_License_Service::is_customer_logged_into_plugin();

		$is_license_verified = Mo_License_Service::is_customer_license_verified();
		if ( ! $is_logged_in || ! $is_license_verified ) {
			$disabled = true;
		}

		if ( $is_license_verified ) {
			$license_expiry_date = Mo_License_Actions_Utility::fetch_license_expiry_date();
			if ( ! empty( $license_expiry_date ) ) {
				$remaining_days = Mo_License_Service::get_expiry_remaining_days( $license_expiry_date );
				if ( $remaining_days < 0 ) {
					echo '<div class="notice notice-error"><p>Your license has expired. Please renew your license to continue using the addons.</p></div>';
					$disabled = true;
				}
			}
		} elseif ( ! $is_logged_in ) {
			echo '<div class="notice notice-warning"><p>Your account and license are not verified. Please login and verify your license key to manage licensed addons.</p></div>';
		} else {
			echo '<div class="notice notice-warning"><p>Your license key is not verified. Please verify your license key to download and configure addons.</p></div>';
		}

		Mo_Options_Addons::init();
		$licensed_addons  = Mo_Options_Addons::get_licensed_addons();
		$available_addons = Mo_Options_Addons::get_available_addons();

		self::display_addon_install_messages();
		?>
		<h1><b>Explore Our Add-ons</b></h1>
		<hr>
		<br>
		<div class="mo-addons-section">
			<h3 class="mo-addons-section-title">Licensed Addons</h3>
			<?php
			if ( ! empty( $licensed_addons ) ) {
				?>
				<div class="mo-addons-container" <?php echo $disabled ? 'style="opacity: 0.5; cursor: not-allowed;"' : ''; ?>>
				<?php
				foreach ( $licensed_addons as $addon_title => $addon_data ) {
					$addon_desc = isset( $addon_data['addonDescription'] ) ? $addon_data['addonDescription'] : '';
					$addon_url  = isset( $addon_data['landingPage'] ) ? $addon_data['landingPage'] : '';
					$addon_icon = isset( $addon_data['addonIcon'] ) ? $addon_data['addonIcon'] : '';
					self::get_addon_tile( $addon_title, $addon_title, $addon_desc, $addon_url, $addon_icon, true, $disabled );
				}
				?>
				</div>
				<?php
			} else {
				?>
				<div class="mo-addons-empty-message">
					<br>
					You have not purchased any Addons.
				</div>
				<?php
			}
			?>
		</div>

		<div class="mo-addons-section">
			<h3 class="mo-addons-section-title">Available Addons</h3>
			<?php
			if ( ! empty( $available_addons ) ) {
				?>
				<div class="mo-addons-container">
				<?php
				foreach ( $available_addons as $addon_title => $addon_data ) {
					$addon_desc = isset( $addon_data['addonDescription'] ) ? $addon_data['addonDescription'] : '';
					$addon_url  = isset( $addon_data['landingPage'] ) ? $addon_data['landingPage'] : '';
					$addon_icon = isset( $addon_data['addonIcon'] ) ? $addon_data['addonIcon'] : '';
					self::get_addon_tile( $addon_title, $addon_title, $addon_desc, $addon_url, $addon_icon, false );
				}
				?>
				</div>
				<?php
			} else {
				?>
				<div class="mo-addons-empty-message">
					You have no other Addons to purchase.
				</div>
				<?php
			}
			?>
		</div>
		<?php
	}

	/**
	 * This function creates a card for displaying the add-ons.
	 *
	 * @param string $addon_name      The addon name identifier.
	 * @param string $addon_title      The display title for the addon.
	 * @param string $addon_desc      The description of the addon.
	 * @param string $addon_url       The URL for more information about the addon.
	 * @param string $addon_icon      The icon URL for the addon.
	 * @param bool   $is_licensed     Whether this is a licensed addon (true) or available addon (false).
	 * @param bool   $disabled        Whether the addon is disabled due to license expiry.
	 * @return void
	 */
	public static function get_addon_tile( $addon_name, $addon_title, $addon_desc, $addon_url, $addon_icon, $is_licensed = true, $disabled = false ) {
		$plan_name    = Mo_Options_Addons::mo_get_addon_plan_name( $addon_name );
		$addon_slug   = Mo_Options_Addons::mo_get_addon_slug( $addon_name );
		$download_url = $plan_name ? Mo_License_API_Client::get_addon_download_url( $plan_name ) : '';

		if ( $addon_slug ) {
			$addon_slug = str_replace( '\\', '/', $addon_slug );
		}
		$is_plugin_active = self::is_plugin_active( $addon_slug );

		?>
			<div class="mo-add-ons-cards mo-bootstrap-mt-3">
				<?php if ( ! empty( $addon_icon ) ) : ?>
					<img src="<?php echo esc_url( $addon_icon ); ?>" class="mo-addons-logo" alt="<?php echo esc_attr( $addon_title ); ?>">
				<?php endif; ?>
				<h4 class="mo-addons-head"><?php echo esc_html( $addon_title ); ?></h4>
				<p class="mo-bootstrap-pe-2 mo-bootstrap-pb-4 mo-bootstrap-ps-4">
					<?php echo esc_html( $addon_desc ); ?>
					<?php if ( $is_licensed && ! empty( $addon_url ) ) : ?>
						<a class="mo-addons-readmore" href="<?php echo esc_url( $addon_url ); ?>" target="_blank">
							Learn More
						</a>
					<?php endif; ?>
				</p>
				<span class="mo-add-ons-tri"></span>
				
				<?php
				if ( $is_licensed ) {
					self::display_addon_settings_button( $addon_slug, $is_plugin_active, $download_url, $addon_name, $disabled );
				} else {
					self::display_upgrade_button( $addon_url );
				}
				?>

			</div>
		<?php
	}

	/**
	 * Check if the addon is active.
	 *
	 * @param string $addon_slug The slug of the addon.
	 * @return bool True if the addon is active, false otherwise.
	 */
	public static function is_plugin_active( $addon_slug ) {
		$is_plugin_active = false;
		if ( ! function_exists( 'is_plugin_active' ) ) {
			require_once ABSPATH . Mo_License_Constants::PLUGIN_FILE_PATH;
		}
		$is_plugin_active = \is_plugin_active( $addon_slug );
		return $is_plugin_active;
	}

	/**
	 * Get the settings URL for the addon.
	 *
	 * @param string $addon_name The addon name.
	 * @return string The settings URL for the addon.
	 */
	public static function get_settings_url( $addon_name ) {
		$settings_url = admin_url();
		$addons       = Mo_License_Config::get_fallback_addons_data();
		foreach ( $addons as $addon ) {
			if ( $addon['addonTitle'] === $addon_name ) {
				$settings_url = admin_url( $addon['settingsPage'] );
				break;
			}
		}
		return $settings_url;
	}

	/**
	 * Display the settings button for the addon.
	 *
	 * @param string $addon_slug The slug of the addon.
	 * @param bool   $is_plugin_active True if the addon is active, false otherwise.
	 * @param string $download_url The download URL for the addon.
	 * @param string $addon_name The name of the addon.
	 * @param bool   $disabled Whether the addon is disabled due to license expiry.
	 * @return void
	 */
	public static function display_addon_settings_button( $addon_slug, $is_plugin_active, $download_url, $addon_name, $disabled = false ) {
		if ( $is_plugin_active && Mo_License_Config::ADDON_CONFIGURE ) {
			$settings_url = self::get_settings_url( $addon_name );
			?>
			<?php if ( $disabled ) { ?>
				<span class="mo-addons-download-button mo-addons-deactivate-button"
					style="background-color:#6c757d; cursor:not-allowed; opacity:0.6;">
					Configure
				</span>
			<?php } else { ?>
				<a class="mo-addons-download-button mo-addons-deactivate-button"
					href="<?php echo esc_url( $settings_url ); ?>"
					style="background-color:#6c757d;"
					title="Go to the Addon Settings"
					<?php echo $disabled ? 'disabled="disabled"' : ''; ?>>
				Configure
				</a>
			<?php } ?>
			<?php
		} elseif ( $is_plugin_active ) {
			?>
			<a class="mo-addons-download-button mo-addons-deactivate-button" href="#" style="background-color: #6c757d; cursor: not-allowed; opacity: 0.6;" title="Plugin is already activated">
				Activated
			</a>
			<?php
		} else {
			?>
			<?php if ( $disabled ) { ?>
				<span class="mo-addons-download-button"
					style="background-color:#6c757d; cursor:not-allowed; opacity:0.6;">
					Install and Activate
				</span>
			<?php } else { ?>
				<a class="mo-addons-download-button" href="#" onclick="mo_install_addon('<?php echo esc_js( $download_url ); ?>', '<?php echo esc_js( $addon_name ); ?>', this); return false;" <?php echo $disabled ? 'disabled="disabled"' : ''; ?>>
					Install and Activate
				</a>
			<?php } ?>
			<?php
		}
	}

	/**
	 * Display the upgrade button for available addons.
	 *
	 * @param string $upgrade_url The URL to upgrade/purchase the addon.
	 * @return void
	 */
	public static function display_upgrade_button( $upgrade_url ) {
		?>
		<a class="mo-addons-upgrade-button" style="cursor: pointer; opacity: 0.8; align-items: center;" href="<?php echo esc_url( $upgrade_url ); ?>" target="_blank">
			Upgrade
		</a>
		<?php
	}

	/**
	 * Display the addon install messages.
	 *
	 * @return void
	 */
	public static function display_addon_install_messages() {
		if ( get_transient( 'addon_install_success' ) && current_user_can( 'manage_options' ) ) {
			echo '<div class="notice notice-success"><p>' . esc_html( get_transient( 'addon_install_success' ) ) . '</p></div>';
			delete_transient( 'addon_install_success' );
		}
		if ( get_transient( 'addon_install_error' ) && current_user_can( 'manage_options' ) ) {
			echo '<div class="notice notice-error"><p>' . esc_html( get_transient( 'addon_install_error' ) ) . '</p></div>';
			delete_transient( 'addon_install_error' );
		}
	}
}
?>
