<?php
/**
 * This file is part of miniOrange WP plugin.
 *
 * @package    miniOrange
 * @author     miniOrange Security Software Pvt. Ltd.
 */

namespace MOSAML\LicenseLibrary\Views;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\LicenseLibrary\Classes\Mo_License_Constants;
use MOSAML\LicenseLibrary\Classes\Mo_License_Dao;
use MOSAML\LicenseLibrary\Mo_License_Config;
use MOSAML\LicenseLibrary\Mo_License_Service;
use MOSAML\LicenseLibrary\Utils\Mo_License_View_Utility;

/**
 * Mo_License_Notice_Views Class contains functions to display the notices related
 * to plugin's licenses.
 */
class Mo_License_Notice_Views {

	/**
	 * Contains the Plugin License Expiry Date.
	 *
	 * @var string
	 */
	protected $expiry_date;

	/**
	 * Contains the days left for plugin license to expire.
	 *
	 * @var int
	 */
	protected $remaining_days;

	/**
	 * Contains values of options required to be displayed in the license notices.
	 *
	 * @var array
	 */
	protected $content_options;

	/**
	 * Returns an array of option names prefixed and suffixed with ## which need to be
	 * replaced in the content printed in the license admin notices.
	 *
	 * @return array
	 */
	private function get_content_options() {

		$expiry_date = Mo_License_Service::get_expiry_date();
		$options     = array(
			'##expiry_date##'     => $expiry_date,
			'##remaining_days##'  => Mo_License_Service::get_expiry_remaining_days( $expiry_date ),
			'##disable_date##'    => Mo_License_Service::get_disable_date( $expiry_date ),
			'##grace_days_left##' => Mo_License_Service::get_grace_days_left( $expiry_date ),
			'##customer_email##'  => Mo_License_Dao::mo_get_option( Mo_License_Config::CUSTOMER_MANUALLY_CONFIGURED_OPTIONS['CUSTOMER_EMAIL_OPTION'] ),
		);
		if ( ! empty( Mo_License_Config::$notice_options ) ) {
			foreach ( Mo_License_Config::$notice_options as $option_text => $option_name ) {
				$options[ '##' . $option_text . '##' ] = Mo_License_Dao::mo_get_option( $option_name );
			}
		}

		return $options;
	}

	/**
	 * Returns the admin notice html view for license information.
	 *
	 * @return string
	 */
	public function get_license_notice() {

		$notice_html     = '';
		$content_options = $this->get_content_options();

		if ( Mo_License_Constants::EPOCH_DATE === $content_options['##expiry_date##'] ) {
			$notice_html = $this->get_tampered_license_notice();
		} elseif ( Mo_License_Service::is_trial_license() ) {
			$notice_html = $this->get_trial_license_notice();
		} elseif ( Mo_License_View_Utility::show_expiry_notice( $content_options['##remaining_days##'] ) ) {
			$notice_html = $this->get_expired_license_notice();
		}

		return $notice_html;
	}

	/**
	 * Prints the html for WordPress admin dashboard widget to show license expiry information.
	 *
	 * @return void
	 */
	public function display_dashboard_widget() {

		$content_options = $this->get_content_options();
		$notice          = Mo_License_View_Utility::get_widget_notice( $content_options );

		$widget_html = '
		<div class="mo-lic-dashboard-widget">
			<div style="width:12%">
			    <img src="' . esc_attr( plugins_url( Mo_License_Constants::MINIORANGE_LOGO_PATH, __DIR__ ) ) . '" alt="miniOrange Logo" width="50px"/>
			</div>
			<div style="width: 85%;font-size: 1.5em;">' . Mo_License_Config::PLUGIN_NAME . '</div>
		</div>';

		if ( ! empty( $notice ) ) {
			$widget_html .= '
            <div class="mo-lic-widget-container">
			    <p class="mo-lic-widget-text">' . $notice . '</p>
		    </div>';
		}

		$widget_html .= '
        <div style="text-align:center">
			<table class="mo-lic-widget-table">
				<tr>
					<td class="mo-lic-widget-table-text-col1"><b>miniOrange Account Email</b></td>
					<td class="mo-lic-widget-table-text-col2">' . esc_html( $content_options['##customer_email##'] ) . '</td>
				</tr>
				<tr>
					<td class="mo-lic-widget-table-text-col1"><b>Plugin License Expiry Date</b></td>
					<td class="mo-lic-widget-table-text-col2">
					    <form name="mo_saml_refresh_expiry" id="' . Mo_License_Constants::DASHBOARD_WIDGET_REFRESH_ID . '" method="POST">
                            ' . wp_nonce_field( Mo_License_Constants::DASHBOARD_WIDGET_REFRESH_ID ) . '
                            <input type="hidden" name="option" value="' . Mo_License_Constants::DASHBOARD_WIDGET_REFRESH_ID . '">
                            <b> ' . esc_html( $content_options['##expiry_date##'] ) . ' </b>
                            <button type="submit" class="mo-lic-widget-refresh">&#x21bb;</button>
                        </form>
					    
					</td>
				</tr>
			</table>
		</div>
		<div class="mo-lic-widget-support-links">
            <div>
                <a href="admin.php?page=' . esc_attr( Mo_License_Config::PLUGIN_SLUG ) . '" style="color:white;">
                <button class="button button-primary button-large"><b>Go to plugin settings</b></button>
                </a>
            </div>
            <div>
                Need any help? Contact us on 
                <a href="mailto:' . esc_attr( Mo_License_Config::SUPPORT_EMAIL ) . '">
                    <b>' . esc_html( Mo_License_Config::SUPPORT_EMAIL ) . '</b>
                </a>
            </div>
		</div>';

        //PHPCS:ignore -- WordPress.Security.EscapeOutput.OutputNotEscaped -- Widget escaped while creation.
		echo $widget_html;
	}

	/**
	 * Returns html for tampered license admin notice.
	 *
	 * @return string
	 */
	private function get_tampered_license_notice() {

		$notice_html = '
			<div style="display:flex;" class="notice notice-error">
                <p class="mo-lic-admin-notice-text">
					<b>ALERT:</b> It seems that your <b><a href="admin.php?page=' . Mo_License_Config::PLUGIN_SLUG . '">' . Mo_License_Config::PLUGIN_NAME . '</a></b> license has been 
					tampered and hence the plugin has stopped working.<br> ' . $this->get_escaped_notice( Mo_License_Config::$tampered_notice_content ) . '
				</p>
            </div>';

		return $notice_html;
	}

	/**
	 * Returns html for domain check failed admin notice.
	 *
	 * @return string
	 */
	public function get_domain_check_failed_notice() {
		$notice_html = '
			<div style="display:flex;" class="notice notice-error">
                <p class="mo-lic-admin-notice-text">
					<b>WARNING:</b> You are using the same license key on the multiple sites. Please <b><a href="admin.php?page=' . Mo_License_Config::PLUGIN_SLUG . '">buy more license keys</a></b> or 
					your plugin will be disabled after ' . Mo_License_Config::FAILED_DOMAIN_CRON_THRESHOLD . ' days.<br> ' . $this->get_escaped_notice( Mo_License_Config::$tampered_notice_content ) . '
				</p>
            </div>';

		return $notice_html;
	}

	/**
	 * Returns html for license expiry admin notice.
	 *
	 * @return string
	 */
	private function get_expired_license_notice() {

		$content_options = $this->get_content_options();
		$plugin_notice   = Mo_License_View_Utility::get_admin_notice_html( Mo_License_View_Utility::get_notice_day_key( $content_options['##remaining_days##'] ), $content_options );
		$notice_html     = '
		<div style="display:flex;" id="' . Mo_License_Config::OPTION_PREFIX . 'license_expiry_notice" class="notice ' . esc_attr( Mo_License_View_Utility::get_expiry_admin_notice_class( $content_options['##remaining_days##'] ) ) . '">
                <div>
                    <img src="' . esc_attr( plugins_url( Mo_License_Constants::MINIORANGE_LOGO_PATH, __DIR__ ) ) . '" class="alignleft mo-lic-admin-notice" alt="miniOrange logo">
                </div>
                <div>
					<div class="alignright" style="padding-top: 12px;">
						<a href="admin.php?page=' . esc_attr( Mo_License_Config::PLUGIN_SLUG ) . '">
						    <button class="button button-primary" type="button">Go to Plugin Settings</button>
						</a>
					</div>
					<h2 class="mo-lic-admin-notice-heading">' . esc_html( $plugin_notice['heading'] ) . '</h2>
					<div class="alignleft">' . $plugin_notice['content'];

		if ( $content_options['##remaining_days##'] > 10 ) {
			$notice_html .= '
						<form method="post" name="" action="" id="' . Mo_License_Constants::ADMIN_NOTICE_DISMISS_ID . '"> ' .
							wp_nonce_field( Mo_License_Constants::ADMIN_NOTICE_DISMISS_ID ) . ' 
							<input type="hidden" name="option" value="' . Mo_License_Constants::ADMIN_NOTICE_DISMISS_ID . '"/>
                        	<input type="submit" value="Dismiss" id="' . Mo_License_Constants::ADMIN_NOTICE_DISMISS_ID . '" class="alignright button button-link" />
							<div class="clear"></div>
						</form>';
		}
		$notice_html .= '
                    </div>
				</div>
            </div>';

		return $notice_html;
	}

	/**
	 * Returns html for trial license admin notice.
	 *
	 * @return string
	 */
	private function get_trial_license_notice() {

		$allowed_tags    = array(
			'p' => array(
				'class' => array(),
			),
			'b' => array(),
			'u' => array(),
			'a' => array(
				'href'   => array(),
				'target' => array(),
				'class'  => array(),
			),
		);
		$content_options = $this->get_content_options();
		$plugin_notice   = Mo_License_View_Utility::get_admin_notice_html( Mo_License_View_Utility::get_notice_day_key( $content_options['##remaining_days##'] ), $content_options );

		$notice_html = '<div class="notice mo_saml_display_flex ' . esc_attr( Mo_License_View_Utility::get_expiry_admin_notice_class( $content_options['##remaining_days##'] ) ) . '">
			<div>
				<img src="' . esc_attr( plugins_url( Mo_License_Constants::MINIORANGE_LOGO_PATH, __DIR__ ) ) . '" class="alignleft mo-lic-admin-notice" alt="miniOrange logo">
			</div>
			<div class="mo_saml_notice_container">
				<div class="alignright mo_saml_notice_btn">
					<a href="admin.php?page=' . esc_attr( Mo_License_Config::PLUGIN_SLUG ) . '">
						<button class="button button-primary" type="button">Go to Plugin Settings</button>
					</a>
				</div>
				<h2 class="mo-lic-admin-notice-heading">' . esc_html( $plugin_notice['heading'] ) . '</h2>
				<div class="alignleft">' . wp_kses( $plugin_notice['content'], $allowed_tags ) . '
				</div>
			</div>
		</div>';

			return $notice_html;
	}


	/**
	 * Escapes the html to be printed.
	 *
	 * @param string $notice_html The html to be escaped.
	 *
	 * @return string
	 */
	private function get_escaped_notice( $notice_html ) {

		return wp_kses(
			$notice_html,
			array(
				'b' => array(),
				'a' => array(
					'href' => array(),
				),
			)
		);
	}
}
