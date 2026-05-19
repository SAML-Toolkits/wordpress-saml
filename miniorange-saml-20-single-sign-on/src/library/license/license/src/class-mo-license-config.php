<?php
/**
 * This file is part of miniOrange WP plugin.
 *
 * @package    miniOrange
 * @author     miniOrange Security Software Pvt. Ltd.
 */

namespace MOSAML\LicenseLibrary;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\LicenseLibrary\Classes\Mo_License_Constants;

/**
 * Contains constants used in the license framework.
 */
class Mo_License_Config {

	const PLUGIN_NAME       = 'miniOrange SAML 2.0 Single Sign-On Plugin';
	const PLUGIN_SLUG       = 'mo_saml_settings';
	const PLUGIN_FILE       = 'miniorange-saml-20-single-sign-on/login.php';
	const SUPPORT_EMAIL     = 'samlsupport@xecurify.com';
	const PLUGIN_VERSION    = '26.0.0';
	const LICENSE_PLAN_NAME = 'wp_saml_sso_multiple_idp_plan';
	const LICENSE_TYPE      = 'WP_SAML_SP_MULTIPLE_IDP_PLUGIN';
	const OPTION_PREFIX     = 'mo_saml_';
	const PLUGIN_TYPE       = 'WP_SS';
	const ACCOUNT_PAGE_URL  = '?page=mo_saml_settings';

	const ADDON_FETCH_PLUGIN_TYPE = 'wp_saml_sso';
	const ADDON_CONFIGURE         = true;
	const PLUGIN_BACKUP_ZIP_NAME  = 'miniorange-saml-20-single-sign-on-standard';
	const ENABLE_UPDATE_FRAMEWORK = true;
	const ALLOW_BACKUP            = false;
	const ENABLE_BACKUP_SETTINGS  = 'mo_saml_enable_backup_settings';

	const CUSTOMER_MANUALLY_CONFIGURED_OPTIONS = array(
		'LICENSE_KEY_OPTION'       => 'sml_lk',
		'CUSTOMER_EMAIL_OPTION'    => 'mo_saml_admin_email',
		'CUSTOMER_PASSWORD_OPTION' => 'mo_saml_admin_password',
	);

	const CUSTOMER_OPTIONS = array(
		'token'  => 'mo_saml_customer_token',
		'id'     => 'mo_saml_admin_customer_key',
		'apiKey' => 'mo_saml_admin_api_key',
		'phone'  => 'mo_saml_admin_phone',
		'tla'    => 'mo_saml_tla',
	);

	const ADD_DASHBOARD_WIDGET = true;

	const LICENSE_CRON_INTERVAL = array(
		'DEFAULT'               => 30,
		'EXPIRY_WITHIN_60_DAYS' => 3,
		'EXPIRED_LICENSE'       => 1,
	);

	const DOMAIN_CHECK_CRON_ENABLED    = true;
	const DOMAIN_CHECK_CRON_INTERVAL   = 3;
	const FAILED_DOMAIN_CRON_THRESHOLD = 15;
	const GRACE_PERIOD_DAYS            = 15;
	const RENEWAL_FAQ                  = 'https://faq.miniorange.com/knowledgebase/how-can-i-renew-my-wordpress-plugin-license/';

	const LICENSE_OPTIONS = array(
		'noOfSP'         => 'no_of_sp',
		'noOfUsers'      => 'mo_idp_usr_lmt',
		'emailRemaining' => 'email_remaining',
		'noOfSubSites'   => 'no_sbs',
		'supportExpiry'  => 'support_expiry_date',
	);

	/**
	 * Contains the content that is displayed in the license admin notice as per
	 * the remaining days of license expiry.
	 *
	 * @var array
	 */
	public static $notice_html = array(

		Mo_License_Constants::EXPIRY_IN_30_TO_60_DAYS => array(
			'heading' => 'Attention: Renewal Required for miniOrange SAML 2.0 Single Sign-On Plugin License',
			'content' => '
			    <p class="mo-lic-admin-notice-text"> 
			        Your license for miniOrange SAML 2.0 Single Sign-On Plugin under account <b>##customer_email##</b> is going to expire 
			        on <b><u>##expiry_date##</u></b>.
                </p>
				<p class="mo-lic-admin-notice-text">
				    <b>Please renew the license before the expiry date. Failure to do so will cause the plugin to stop working. You can renew 
				    the license by following the <a href="https://faq.miniorange.com/knowledgebase/how-can-i-renew-my-wordpress-plugin-license/" 
			        target="_blank">steps mentioned here</a>.</b>
			    </p>
				<p class="mo-lic-admin-notice-text"> 
				    Please note that a notification will be sent to the email address <b>##customer_email##</b>. In case you do not receive 
				    the notification, are unable to access this mailbox, or have any questions regarding renewal, kindly contact us 
				    immediately at <a href="mailto:samlsupport@xecurify.com"><b>samlsupport@xecurify.com</b></a>. 
				</p>',
		),

		Mo_License_Constants::EXPIRY_IN_10_TO_30_DAYS => array(
			'heading' => 'Attention: Renewal Required for miniOrange SAML 2.0 Single Sign-On Plugin License',
			'content' => '
			    <p class="mo-lic-admin-notice-text"> 
			        Your license for miniOrange SAML 2.0 Single Sign-On Plugin under account <b>##customer_email##</b> is going to expire 
			        on <b><u>##expiry_date##</u></b>.
                </p>
				<p class="mo-lic-admin-notice-text">
				    <b>Please renew the license before the expiry date. Failure to do so will cause the plugin to stop working. You can renew 
				    the license by following the <a href="https://faq.miniorange.com/knowledgebase/how-can-i-renew-my-wordpress-plugin-license/" 
			        target="_blank">steps mentioned here</a>.</b>
			    </p>
				<p class="mo-lic-admin-notice-text"> 
				    Please note that a notification will be sent to the email address <b>##customer_email##</b>. In case you do not receive 
				    the notification, are unable to access this mailbox, or have any questions regarding renewal, kindly contact us 
				    immediately at <a href="mailto:samlsupport@xecurify.com"><b>samlsupport@xecurify.com</b></a>. 
				</p>',
		),

		Mo_License_Constants::EXPIRY_IN_10_DAYS       => array(
			'heading' => 'Immediate Attention Required: Renew your miniOrange SAML 2.0 Single Sign-On Plugin License',
			'content' => '
			    <p class="mo-lic-admin-notice-text"> 
			        Your license for miniOrange SAML 2.0 Single Sign-On Plugin under account <b>##customer_email##</b> is going to expire 
			        on <b><u>##expiry_date##</u></b>.
                </p>
				<p class="mo-lic-admin-notice-text">
				    <b>Please renew the license before the expiry date. Failure to do so will cause the plugin to stop working. You can renew the 
					license by following the <a href="https://faq.miniorange.com/knowledgebase/how-can-i-renew-my-wordpress-plugin-license/" target="_blank">
				    steps mentioned here</a>.</b>
			    </p>
				<p class="mo-lic-admin-notice-text"> 
				    Please note that a notification will be sent to the email address <b> ##customer_email## </b>. In case you do not receive 
				    the notification, are unable to access this mailbox, or have any questions regarding renewal, kindly contact us 
				    immediately at <a href="mailto:samlsupport@xecurify.com"><b>samlsupport@xecurify.com</b></a>. 
				</p>',
		),

		Mo_License_Constants::GRACE_PERIOD_STARTED    => array(
			'heading' => 'Immediate Action Required: Renew your miniOrange SAML 2.0 Single Sign-On Plugin License',
			'content' => '
			    <p class="mo-lic-admin-notice-text"> 
			        Your license for miniOrange SAML 2.0 Single Sign-On Plugin under account <b>##customer_email##</b> has expired on <b>
                    <u>##expiry_date##</u></b>. <b>Your plugin license has expired and is currently in grace period for renewal.</b> The 
                    plugin will become non-functional once the grace period is over i.e. on <b><u>##disable_date##</u></b>.
                </p>
				<p class="mo-lic-admin-notice-text">
				    <b>You can renew the license by following the 
				    <a href="https://faq.miniorange.com/knowledgebase/how-can-i-renew-my-wordpress-plugin-license/" target="_blank">
				    steps mentioned here</a>.</b>
			    </p>
				<p class="mo-lic-admin-notice-text"> 
				    Please note that a notification will be sent to the email address <b>##customer_email##</b>. In case you do not receive 
				    the notification, are unable to access this mailbox, or have any questions regarding renewal, kindly contact us 
				    immediately at <a href="mailto:samlsupport@xecurify.com"><b>samlsupport@xecurify.com</b></a>. 
				</p>',
		),

		Mo_License_Constants::GRACE_PERIOD_EXPIRED    => array(
			'heading' => 'Immediate Action Required: Renew your miniOrange SAML 2.0 Single Sign-On Plugin License',
			'content' => '
                <p class="mo-lic-admin-notice-text"> 
			        Your license for miniOrange SAML 2.0 Single Sign-On Plugin under account <b>##customer_email##</b> has already expired 
			        on <b><u>##expiry_date##</u></b>.
                </p>
				<p class="mo-lic-admin-notice-text">
				    Your grace period for license renewal has expired. <span style="font-size: 16px;color: red;"><u>SSO has stopped working 
				    on your site</u></span> and hence, your users will not be able to login through SSO anymore. <b>Renew your plugin license
				    immediately</b> by following the 
				    <a href="https://faq.miniorange.com/knowledgebase/how-can-i-renew-my-wordpress-plugin-license/" target="_blank">
				    steps mentioned here</a> to restore Single Sign-On on your site.
			    </p>
				<p class="mo-lic-admin-notice-text"> 
                    Please note that a notification will be sent to the email address <b>##customer_email##</b>. In case you do not receive 
                    the notification, are unable to access this mailbox, or have any questions regarding renewal, kindly contact us 
                    immediately at <a href="mailto:samlsupport@xecurify.com"><b>samlsupport@xecurify.com</b></a>.
                </p>',
		),

		Mo_License_Constants::TRIAL_PERIOD_STARTED    => array(
			'heading' => 'Trial: Purchase miniOrange SAML 2.0 Single Sign-On Plugin License',
			'content' => '
                <p class="mo-lic-admin-notice-text"> 
			        Your TRIAL license for miniOrange SAML 2.0 Single Sign On plugin has been activated and will be valid till <b><u>##expiry_date##</u></b>.
                </p>
				<p class="mo-lic-admin-notice-text">
				    If you need any help in setting up the SSO, please reach out to us at <a href="mailto:samlsupport@xecurify.com" class="text-primary"><b>samlsupport@xecurify.com</b></a>.
			    </p>',
		),

		Mo_License_Constants::TRIAL_PERIOD_EXPIRED    => array(
			'heading' => 'Trial: Purchase miniOrange SAML 2.0 Single Sign-On Plugin License',
			'content' => '
                <p class="mo-lic-admin-notice-text"> 
			        Your TRIAL license for miniOrange SAML 2.0 Single Sign On plugin has been expired on <b><u>##expiry_date##</u></b>.
                </p>
				<p class="mo-lic-admin-notice-text">
				    Please <b><a href="https://plugins.miniorange.com/wordpress-single-sign-on-sso#pricing" target="_blank">purchase the plugin</a></b> or contact us at <a href="mailto:samlsupport@xecurify.com" class="text-primary"><b>samlsupport@xecurify.com</b></a>.
			    </p>',
		),
	);

	/**
	 * Contains the options whose values need to be fetched from the database and replaced
	 * in the license admin notice content. The key is the name used in the content of the
	 * admin notice. Value is the database option name from where the value would be
	 * fetched and replaced.
	 *
	 * @var array
	 */
	public static $notice_options = array();

	/**
	 * Contains the content for admin notice which would be displayed when the plugin's
	 * license expiry date has been tampered with.
	 *
	 * @var string
	 */
	public static $tampered_notice_content = '
		Please click on the <b>Sync your License</b> button in the Account Info tab to sync the license details.
		Please reach out to us at <a href="mailto:samlsupport@xecurify.com">samlsupport@xecurify.com</a> if the 
		issue persists.';

	/**
	 * Fallback addons data.
	 *
	 * @return array Fallback addons data.
	 */
	public static function get_fallback_addons_data() {
		return array(
			array(
				'addonTitle'       => 'WordPress Page Restriction Premium Plugin',
				'addonDescription' => 'Page and Post Restriction plugin restricts WordPress pages and posts based on User Roles and User\'s Login Status.',
				'addonIcon'        => 'https://mo-marketplace.s3.us-east-1.amazonaws.com/images/addons/wordpress-integration-page-post.webp',
				'landingPage'      => 'https://plugins.miniorange.com/wordpress-page-restriction',
				'settingsPage'     => 'admin.php?page=page_restriction',
			),
			array(
				'addonTitle'       => 'WordPress Media Restriction Add-on',
				'addonDescription' => 'The Media Restriction add-on restricts unauthorized users from accessing the media files on your WordPress site.',
				'addonIcon'        => 'https://mo-marketplace.s3.us-east-1.amazonaws.com/images/addons/wordpress-integration-media.webp',
				'landingPage'      => 'https://plugins.miniorange.com/wordpress-media-restriction',
				'settingsPage'     => 'admin.php?page=mo_media_restrict',
			),
			array(
				'addonTitle'       => 'WordPress Integrators Add-on',
				'addonDescription' => 'The add-on supports various integrators like Paid Membership Pro, WooCommerce, BuddyPress, LearnDash, WPMembers, and MemberPress etc.',
				'addonIcon'        => 'https://mo-marketplace.s3.us-east-1.amazonaws.com/images/addons/wordpress-integration-wp-members.webp',
				'landingPage'      => 'https://plugins.miniorange.com/wordpress-single-sign-on-sso-integrators-addon-setup',
				'settingsPage'     => 'admin.php?page=mowi-integrators',
			),
			array(
				'addonTitle'       => 'SCIM User Provisioning Premium Plugin',
				'addonDescription' => 'SCIM User Provisioning allows you to sync user\'s creation, updation and deletion from your IDP to WordPress site.',
				'addonIcon'        => 'https://mo-marketplace.s3.us-east-1.amazonaws.com/images/addons/wordpress-integration-scim.webp',
				'landingPage'      => 'https://plugins.miniorange.com/wordpress-user-provisioning',
				'settingsPage'     => 'admin.php?page=user_provisioning',
			),
			array(
				'addonTitle'       => 'WordPress Guest User Login Add-on',
				'addonDescription' => 'Guest User Login allows users to login to WordPress site without creating a WordPress user account for them.',
				'addonIcon'        => 'https://mo-marketplace.s3.us-east-1.amazonaws.com/images/addons/wordpress-integration-guest-user-login.webp',
				'landingPage'      => 'https://plugins.miniorange.com/guest-user-login',
				'settingsPage'     => 'admin.php?page=mo_guest_login_settings',
			),
			array(
				'addonTitle'       => 'WordPress SSO Login Audit Add-on',
				'addonDescription' => 'SSO Login Audit captures and tracks all the SSO users and generates reports.',
				'addonIcon'        => 'https://mo-marketplace.s3.us-east-1.amazonaws.com/images/addons/wordpress-integration-login-audit.webp',
				'landingPage'      => 'https://plugins.miniorange.com/wordpress-sso-login-audit',
				'settingsPage'     => 'admin.php?page=sso_login_audit',
			),
			array(
				'addonTitle'       => 'SSO Session Management Add-on',
				'addonDescription' => 'SSO session management add-on manages the login session time of your users based on their WordPress roles.',
				'addonIcon'        => 'https://mo-marketplace.s3.us-east-1.amazonaws.com/images/addons/wordpress-integration-session-manage.webp',
				'landingPage'      => 'https://plugins.miniorange.com/sso-session-management',
				'settingsPage'     => 'admin.php?page=session_add_on',
			),
			array(
				'addonTitle'       => 'WordPress Attribute-Based Redirection Add-on',
				'addonDescription' => 'Attribute-Based Redirection plugin can be used to restrict and redirect users to different URLs based on SAML attributes.',
				'addonIcon'        => 'https://mo-marketplace.s3.us-east-1.amazonaws.com/images/addons/wordpress-integrations-attr-map.webp',
				'landingPage'      => 'https://plugins.miniorange.com/wordpress-attribute-based-redirection-restriction',
				'settingsPage'     => 'admin.php?page=attribute_redirection',
			),
			array(
				'addonTitle'       => 'WordPress IP Whitelisting Add-on',
				'addonDescription' => 'WordPress IP Whitelisting addon allows the whitelisted users to bypass redirection to the IDP for authentication based on their IP address.',
				'addonIcon'        => 'https://mo-marketplace.s3.us-east-1.amazonaws.com/images/addons/wordpress-integration-ip-whitelist.webp',
				'landingPage'      => 'https://plugins.miniorange.com/wordpress-ip-whitelisting',
				'settingsPage'     => 'admin.php?page=mo-sso-ip-whitelisting',
			),
			array(
				'addonTitle'       => 'WordPress Profile Picture Mapping Add-on',
				'addonDescription' => 'WordPress Profile Picture Mapping addon allows to map the user profile picture from IDP to the WordPress user profile.',
				'addonIcon'        => 'https://mo-marketplace.s3.us-east-1.amazonaws.com/images/addons/wordpress-integration-ip-whitelist.webp',
				'landingPage'      => 'https://plugins.miniorange.com/wordpress-ip-whitelisting',
				'settingsPage'     => 'admin.php?page=mo_propicmap',
			),
		);
	}

	/**
	 * Whether backup is allowed for the plugin.
	 *
	 * @return bool
	 */
	public static function allow_backup() {
		$enable_backup = get_option( self::ENABLE_BACKUP_SETTINGS, 'checked' );
		return 'checked' === $enable_backup ? true : self::ALLOW_BACKUP;
	}
}
