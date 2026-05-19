<?php
/**
 * Plugin File Path Constants.
 *
 * This file contains all file path constants used throughout the plugin.
 * This is part of Wordfence security fixes to centralize file includes.
 *
 * @package miniorange-saml-20-single-sign-on
 */

namespace MOSAML\SRC\Constant;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Plugin File Path Constants.
 *
 * Contains all file path constants for includes and requires.
 *
 * @package miniorange-saml-20-single-sign-on
 */
class Plugin_Files_Constants {

	/**
	 * Component template files.
	 *
	 * @var string
	 */
	const ATTRIBUTE_DROPDOWN                  = MOSAML_PLUGIN_DIR . 'src' . DIRECTORY_SEPARATOR . 'template' . DIRECTORY_SEPARATOR . 'components' . DIRECTORY_SEPARATOR . 'attribute-dropdown.php';
	const NO_IDP_CONFIGURED_STRIP             = MOSAML_PLUGIN_DIR . 'src' . DIRECTORY_SEPARATOR . 'template' . DIRECTORY_SEPARATOR . 'components' . DIRECTORY_SEPARATOR . 'no-idp-configured-strip.php';
	const LOGIN_REQUIRED_STRIP                = MOSAML_PLUGIN_DIR . 'src' . DIRECTORY_SEPARATOR . 'template' . DIRECTORY_SEPARATOR . 'components' . DIRECTORY_SEPARATOR . 'login-required-strip.php';
	const LICENSE_VERIFICATION_REQUIRED_STRIP = MOSAML_PLUGIN_DIR . 'src' . DIRECTORY_SEPARATOR . 'template' . DIRECTORY_SEPARATOR . 'components' . DIRECTORY_SEPARATOR . 'license-verification-required-strip.php';
	const LICENSE_EXPIRED_STRIP               = MOSAML_PLUGIN_DIR . 'src' . DIRECTORY_SEPARATOR . 'template' . DIRECTORY_SEPARATOR . 'components' . DIRECTORY_SEPARATOR . 'license-expired-strip.php';
	const CERTIFICATE_EXPIRED_SECURITY_ALERT  = MOSAML_PLUGIN_DIR . 'src' . DIRECTORY_SEPARATOR . 'template' . DIRECTORY_SEPARATOR . 'components' . DIRECTORY_SEPARATOR . 'certificate-expired-security-alert.php';
	const IDP_LICENSE_LIMIT_EXCEEDED_STRIP    = MOSAML_PLUGIN_DIR . 'src' . DIRECTORY_SEPARATOR . 'template' . DIRECTORY_SEPARATOR . 'components' . DIRECTORY_SEPARATOR . 'idp-license-limit-exceeded-strip.php';

	/**
	 * Main template files.
	 *
	 * @var string
	 */
	const TEMPLATE_TEST_CONFIG                    = MOSAML_PLUGIN_DIR . 'src' . DIRECTORY_SEPARATOR . 'template' . DIRECTORY_SEPARATOR . 'test-config.php';
	const TEMPLATE_TEST_CONFIG_CURR_ENV_ERROR     = MOSAML_PLUGIN_DIR . 'src' . DIRECTORY_SEPARATOR . 'template' . DIRECTORY_SEPARATOR . 'test-config-current-environment-error.php';
	const TEMPLATE_ADMIN_MENU_PAGE                = MOSAML_PLUGIN_DIR . 'src' . DIRECTORY_SEPARATOR . 'template' . DIRECTORY_SEPARATOR . 'admin-menu-page.php';
	const TEMPLATE_CUSTOM_MODAL                   = MOSAML_PLUGIN_DIR . 'src' . DIRECTORY_SEPARATOR . 'template' . DIRECTORY_SEPARATOR . 'custom-notice-modal.php';
	const TEMPLATE_SELECTED_ENVIRONMENT           = MOSAML_PLUGIN_DIR . 'src' . DIRECTORY_SEPARATOR . 'template' . DIRECTORY_SEPARATOR . 'selected_environment.php';
	const TEMPLATE_DATABASE_UPDATE_REQUIRED       = MOSAML_PLUGIN_DIR . 'src' . DIRECTORY_SEPARATOR . 'template' . DIRECTORY_SEPARATOR . 'database-update-required.php';
	const TEMPLATE_DATABASE_UPDATE_ADMIN_NOTICE   = MOSAML_PLUGIN_DIR . 'src' . DIRECTORY_SEPARATOR . 'template' . DIRECTORY_SEPARATOR . 'database-update-admin-notice.php';
	const TEMPLATE_MISSING_EXTENSIONS             = MOSAML_PLUGIN_DIR . 'src' . DIRECTORY_SEPARATOR . 'template' . DIRECTORY_SEPARATOR . 'missing-extensions.php';
	const TEMPLATE_BULK_ACTION_CONFIRMATION       = MOSAML_PLUGIN_DIR . 'src' . DIRECTORY_SEPARATOR . 'template' . DIRECTORY_SEPARATOR . 'bulk-action-confirmation.php';
	const TEMPLATE_UPLOAD_IDP_METADATA            = MOSAML_PLUGIN_DIR . 'src' . DIRECTORY_SEPARATOR . 'template' . DIRECTORY_SEPARATOR . 'upload-idp-metadata.php';
	const TEMPLATE_SELECT_IDP_GRID                = MOSAML_PLUGIN_DIR . 'src' . DIRECTORY_SEPARATOR . 'template' . DIRECTORY_SEPARATOR . 'select-idp-grid.php';
	const TEMPLATE_IDP_MANUAL_CONFIG              = MOSAML_PLUGIN_DIR . 'src' . DIRECTORY_SEPARATOR . 'template' . DIRECTORY_SEPARATOR . 'idp-manual-config.php';
	const TEMPLATE_IDP_METADATA_SYNC              = MOSAML_PLUGIN_DIR . 'src' . DIRECTORY_SEPARATOR . 'template' . DIRECTORY_SEPARATOR . 'idp-metadata-sync.php';
	const TEMPLATE_SP_SETUP                       = MOSAML_PLUGIN_DIR . 'src' . DIRECTORY_SEPARATOR . 'template' . DIRECTORY_SEPARATOR . 'sp-setup.php';
	const TEMPLATE_SP_METADATA_TAB                = MOSAML_PLUGIN_DIR . 'src' . DIRECTORY_SEPARATOR . 'template' . DIRECTORY_SEPARATOR . 'sp-metadata-tab.php';
	const TEMPLATE_SP_METADATA                    = MOSAML_PLUGIN_DIR . 'src' . DIRECTORY_SEPARATOR . 'template' . DIRECTORY_SEPARATOR . 'sp-metadata.php';
	const TEMPLATE_CUSTOM_CERTIFICATE             = MOSAML_PLUGIN_DIR . 'src' . DIRECTORY_SEPARATOR . 'template' . DIRECTORY_SEPARATOR . 'custom-certificate.php';
	const TEMPLATE_LOGIN_PAGE_SSO_BUTTON          = MOSAML_PLUGIN_DIR . 'src' . DIRECTORY_SEPARATOR . 'template' . DIRECTORY_SEPARATOR . 'login-page-sso-button.php';
	const TEMPLATE_LOGIN_BUTTON_HTML              = MOSAML_PLUGIN_DIR . 'src' . DIRECTORY_SEPARATOR . 'template' . DIRECTORY_SEPARATOR . 'login-button-html.php';
	const TEMPLATE_FEEDBACK_FORM                  = MOSAML_PLUGIN_DIR . 'src' . DIRECTORY_SEPARATOR . 'template' . DIRECTORY_SEPARATOR . 'feedback-form.php';
	const TEMPLATE_SUPPORT_FORM                   = MOSAML_PLUGIN_DIR . 'src' . DIRECTORY_SEPARATOR . 'template' . DIRECTORY_SEPARATOR . 'support-form.php';
	const TEMPLATE_KEEP_SETTING_INTACT            = MOSAML_PLUGIN_DIR . 'src' . DIRECTORY_SEPARATOR . 'template' . DIRECTORY_SEPARATOR . 'keep-setting-intact.php';
	const TEMPLATE_BACKUP_SETTINGS_ON_UPGRADE     = MOSAML_PLUGIN_DIR . 'src' . DIRECTORY_SEPARATOR . 'template' . DIRECTORY_SEPARATOR . 'backup-settings-on-upgrade.php';
	const TEMPLATE_MANAGE_MULTIPLE_ENVIRONMENTS   = MOSAML_PLUGIN_DIR . 'src' . DIRECTORY_SEPARATOR . 'template' . DIRECTORY_SEPARATOR . 'manage-multiple-environments.php';
	const TEMPLATE_MULTIPLE_ENVIRONMENT_MENU_PAGE = MOSAML_PLUGIN_DIR . 'src' . DIRECTORY_SEPARATOR . 'template' . DIRECTORY_SEPARATOR . 'multiple-environment-menu-page.php';
	const TEMPLATE_TROUBLESHOOT_MENU_PAGE         = MOSAML_PLUGIN_DIR . 'src' . DIRECTORY_SEPARATOR . 'template' . DIRECTORY_SEPARATOR . 'troubleshoot-menu-page.php';
	const TEMPLATE_DEBUG_LOGGER                   = MOSAML_PLUGIN_DIR . 'src' . DIRECTORY_SEPARATOR . 'template' . DIRECTORY_SEPARATOR . 'debug-logger.php';
	const TEMPLATE_TEST_CONFIG_ATTRIBUTE_TABLE    = MOSAML_PLUGIN_DIR . 'src' . DIRECTORY_SEPARATOR . 'template' . DIRECTORY_SEPARATOR . 'test-config-attribute-table.php';
	const TEMPLATE_SELECTED_ENVIRONMENT_SIDEBAR   = MOSAML_PLUGIN_DIR . 'src' . DIRECTORY_SEPARATOR . 'template' . DIRECTORY_SEPARATOR . 'selected_environment-sidebar-ui.php';
	const TEMPLATE_ADVERTISE_PRODUCTS_NOTICE      = MOSAML_PLUGIN_DIR . 'src' . DIRECTORY_SEPARATOR . 'template' . DIRECTORY_SEPARATOR . 'advertise-products-notice.php';
	const TEMPLATE_ADVERTISE_NOTICES_SALESFORCE   = MOSAML_PLUGIN_DIR . 'src' . DIRECTORY_SEPARATOR . 'template' . DIRECTORY_SEPARATOR . 'advertise-notices' . DIRECTORY_SEPARATOR . 'salesforce-notice.php';
	const TEMPLATE_ADVERTISE_NOTICES_AZURE        = MOSAML_PLUGIN_DIR . 'src' . DIRECTORY_SEPARATOR . 'template' . DIRECTORY_SEPARATOR . 'advertise-notices' . DIRECTORY_SEPARATOR . 'azure-notice.php';

	/**
	 * SSO Redirection Settings template files.
	 *
	 * @var string
	 */
	const TEMPLATE_SSO_REDIRECTION_MAIN        = MOSAML_PLUGIN_DIR . 'src' . DIRECTORY_SEPARATOR . 'template' . DIRECTORY_SEPARATOR . 'sso-redirection-settings' . DIRECTORY_SEPARATOR . 'main.php';
	const TEMPLATE_SSO_LINKS_AND_BUTTONS       = MOSAML_PLUGIN_DIR . 'src' . DIRECTORY_SEPARATOR . 'template' . DIRECTORY_SEPARATOR . 'sso-redirection-settings' . DIRECTORY_SEPARATOR . 'sso-links-and-buttons.php';
	const TEMPLATE_SSO_REDIRECTION_SETTINGS    = MOSAML_PLUGIN_DIR . 'src' . DIRECTORY_SEPARATOR . 'template' . DIRECTORY_SEPARATOR . 'sso-redirection-settings' . DIRECTORY_SEPARATOR . 'redirection-settings.php';
	const TEMPLATE_SSO_BUTTON_SUBSECTION       = MOSAML_PLUGIN_DIR . 'src' . DIRECTORY_SEPARATOR . 'template' . DIRECTORY_SEPARATOR . 'sso-redirection-settings' . DIRECTORY_SEPARATOR . 'sso-button-subsection.php';
	const TEMPLATE_SSO_BUTTON                  = MOSAML_PLUGIN_DIR . 'src' . DIRECTORY_SEPARATOR . 'template' . DIRECTORY_SEPARATOR . 'sso-redirection-settings' . DIRECTORY_SEPARATOR . 'sso-button.php';
	const TEMPLATE_SSO_LINKS                   = MOSAML_PLUGIN_DIR . 'src' . DIRECTORY_SEPARATOR . 'template' . DIRECTORY_SEPARATOR . 'sso-redirection-settings' . DIRECTORY_SEPARATOR . 'sso-links.php';
	const TEMPLATE_SHORTCODE_WIDGET_SETTINGS   = MOSAML_PLUGIN_DIR . 'src' . DIRECTORY_SEPARATOR . 'template' . DIRECTORY_SEPARATOR . 'sso-redirection-settings' . DIRECTORY_SEPARATOR . 'shortcode-and-widget-settings.php';
	const TEMPLATE_AUTO_REDIRECT_FROM_SITE     = MOSAML_PLUGIN_DIR . 'src' . DIRECTORY_SEPARATOR . 'template' . DIRECTORY_SEPARATOR . 'sso-redirection-settings' . DIRECTORY_SEPARATOR . 'auto-redirect-from-site.php';
	const TEMPLATE_AUTO_REDIRECT_FROM_WP_LOGIN = MOSAML_PLUGIN_DIR . 'src' . DIRECTORY_SEPARATOR . 'template' . DIRECTORY_SEPARATOR . 'sso-redirection-settings' . DIRECTORY_SEPARATOR . 'auto-redirect-from-wp-login.php';
	const TEMPLATE_REDIRECTION_AFTER_SSO       = MOSAML_PLUGIN_DIR . 'src' . DIRECTORY_SEPARATOR . 'template' . DIRECTORY_SEPARATOR . 'sso-redirection-settings' . DIRECTORY_SEPARATOR . 'redirection-after-sso.php';

	/**
	 * Attribute and Role Mapping template files.
	 *
	 * @var string
	 */
	const TEMPLATE_ATTRIBUTE_AND_ROLE_MAPPING_TAB = MOSAML_PLUGIN_DIR . 'src' . DIRECTORY_SEPARATOR . 'template' . DIRECTORY_SEPARATOR . 'attribute-and-role-mapping-settings' . DIRECTORY_SEPARATOR . 'attribute-and-role-mapping-tab.php';
	const TEMPLATE_ATTRIBUTE_MAPPING_SUBTAB       = MOSAML_PLUGIN_DIR . 'src' . DIRECTORY_SEPARATOR . 'template' . DIRECTORY_SEPARATOR . 'attribute-and-role-mapping-settings' . DIRECTORY_SEPARATOR . 'attribute-mapping-subtab.php';
	const TEMPLATE_ROLE_MAPPING_SUBTAB            = MOSAML_PLUGIN_DIR . 'src' . DIRECTORY_SEPARATOR . 'template' . DIRECTORY_SEPARATOR . 'attribute-and-role-mapping-settings' . DIRECTORY_SEPARATOR . 'role-mapping-subtab.php';
	const TEMPLATE_ADVANCED_SETTINGS_SUBTAB       = MOSAML_PLUGIN_DIR . 'src' . DIRECTORY_SEPARATOR . 'template' . DIRECTORY_SEPARATOR . 'attribute-and-role-mapping-settings' . DIRECTORY_SEPARATOR . 'advanced-settings-subtab.php';

	/**
	 * Advanced Settings template files.
	 *
	 * @var string
	 */
	const TEMPLATE_ADVANCED_SETTING = MOSAML_PLUGIN_DIR . 'src' . DIRECTORY_SEPARATOR . 'template' . DIRECTORY_SEPARATOR . 'advanced-setting.php';

	/**
	 * Account Settings template files.
	 *
	 * @var string
	 */
	const TEMPLATE_ACCOUNT_REGISTRATION = MOSAML_PLUGIN_DIR . 'src' . DIRECTORY_SEPARATOR . 'template' . DIRECTORY_SEPARATOR . 'account-settings' . DIRECTORY_SEPARATOR . 'account-registration.php';
	const TEMPLATE_ACCOUNT_LOGIN        = MOSAML_PLUGIN_DIR . 'src' . DIRECTORY_SEPARATOR . 'template' . DIRECTORY_SEPARATOR . 'account-settings' . DIRECTORY_SEPARATOR . 'account-login.php';
	const TEMPLATE_LICENSE_VERIFICATION = MOSAML_PLUGIN_DIR . 'src' . DIRECTORY_SEPARATOR . 'template' . DIRECTORY_SEPARATOR . 'account-settings' . DIRECTORY_SEPARATOR . 'license-verification.php';
	const TEMPLATE_ACCOUNT_INFO_FREE    = MOSAML_PLUGIN_DIR . 'src' . DIRECTORY_SEPARATOR . 'template' . DIRECTORY_SEPARATOR . 'account-settings' . DIRECTORY_SEPARATOR . 'account-info-free.php';
	const TEMPLATE_ACCOUNT_INFO         = MOSAML_PLUGIN_DIR . 'src' . DIRECTORY_SEPARATOR . 'template' . DIRECTORY_SEPARATOR . 'account-settings' . DIRECTORY_SEPARATOR . 'account-info.php';

	/**
	 * Migration handler files.
	 *
	 * @var string
	 */
	const HANDLER_MIGRATION_VERSION_MAPPINGS_DIR           = MOSAML_PLUGIN_DIR . 'src' . DIRECTORY_SEPARATOR . 'handler' . DIRECTORY_SEPARATOR . 'migration' . DIRECTORY_SEPARATOR . 'version-mappings' . DIRECTORY_SEPARATOR;
	const HANDLER_MIGRATION_LEGACY_OPTIONS_ENUM_STANDARD   = MOSAML_PLUGIN_DIR . 'src' . DIRECTORY_SEPARATOR . 'handler' . DIRECTORY_SEPARATOR . 'migration' . DIRECTORY_SEPARATOR . 'version-mappings' . DIRECTORY_SEPARATOR . 'class-legacy-options-enum-standard.php';
	const HANDLER_MIGRATION_LEGACY_OPTIONS_SERVICE         = MOSAML_PLUGIN_DIR . 'src' . DIRECTORY_SEPARATOR . 'handler' . DIRECTORY_SEPARATOR . 'migration' . DIRECTORY_SEPARATOR . 'class-legacy-options-service.php';
	const HANDLER_MIGRATION_LEGACY_OPTIONS_ENUM_PREMIUM    = MOSAML_PLUGIN_DIR . 'src' . DIRECTORY_SEPARATOR . 'handler' . DIRECTORY_SEPARATOR . 'migration' . DIRECTORY_SEPARATOR . 'version-mappings' . DIRECTORY_SEPARATOR . 'class-legacy-options-enum-premium.php';
	const HANDLER_MIGRATION_LEGACY_OPTIONS_ENUM_ENTERPRISE = MOSAML_PLUGIN_DIR . 'src' . DIRECTORY_SEPARATOR . 'handler' . DIRECTORY_SEPARATOR . 'migration' . DIRECTORY_SEPARATOR . 'version-mappings' . DIRECTORY_SEPARATOR . 'class-legacy-options-enum-enterprise.php';
	const HANDLER_MIGRATION_MAPPER_ENVIRONMENT_OBJECT      = MOSAML_PLUGIN_DIR . 'src' . DIRECTORY_SEPARATOR . 'handler' . DIRECTORY_SEPARATOR . 'migration' . DIRECTORY_SEPARATOR . 'mapper' . DIRECTORY_SEPARATOR . 'object' . DIRECTORY_SEPARATOR . 'class-environmnet-object.php';

	/**
	 * Module files.
	 *
	 * @var string
	 */
	const MODULE_PREMIUM_CLI = MOSAML_PLUGIN_DIR . 'module' . DIRECTORY_SEPARATOR . 'premium' . DIRECTORY_SEPARATOR . 'cli' . DIRECTORY_SEPARATOR . 'class-mosaml-cli.php';

	/**
	 * Library files.
	 *
	 * @var string
	 */
	const LIBRARY_XMLSECLIBS = MOSAML_PLUGIN_DIR . 'src' . DIRECTORY_SEPARATOR . 'library' . DIRECTORY_SEPARATOR . 'robrichards' . DIRECTORY_SEPARATOR . 'xmlseclibs' . DIRECTORY_SEPARATOR . 'xmlseclibs.php';

	/**
	 * WordPress core files.
	 *
	 * @var string
	 */
	const WP_ADMIN_INCLUDES_FILE         = 'wp-admin' . DIRECTORY_SEPARATOR . 'includes' . DIRECTORY_SEPARATOR . 'file.php';
	const WP_ADMIN_INCLUDES_PLUGIN_FILE  = 'wp-admin' . DIRECTORY_SEPARATOR . 'includes' . DIRECTORY_SEPARATOR . 'plugin.php';
	const WP_ADMIN_INCLUDES_UPGRADE_FILE = 'wp-admin' . DIRECTORY_SEPARATOR . 'includes' . DIRECTORY_SEPARATOR . 'upgrade.php';
	const WP_CONFIG_PHP_FILE             = 'wp-config.php';

	/**
	 * Autoloader files.
	 *
	 * @var string
	 */
	const LIBRARY_LICENSE_AUTOLOADER     = MOSAML_PLUGIN_DIR . 'src' . DIRECTORY_SEPARATOR . 'library' . DIRECTORY_SEPARATOR . 'license' . DIRECTORY_SEPARATOR . 'license' . DIRECTORY_SEPARATOR . 'autoloader.php';
	const LIBRARY_ROBRICHARDS_AUTOLOADER = MOSAML_PLUGIN_DIR . 'src' . DIRECTORY_SEPARATOR . 'library' . DIRECTORY_SEPARATOR . 'robrichards' . DIRECTORY_SEPARATOR . 'autoloader.php';

	/**
	 * Integration files.
	 *
	 * @var string
	 */
	const INTEGRATION_FUNCTIONS = MOSAML_PLUGIN_DIR . 'src' . DIRECTORY_SEPARATOR . 'integration' . DIRECTORY_SEPARATOR . 'integration-functions.php';

	/**
	 * License expiry page template files.
	 *
	 * @var string
	 */
	const TEMPLATE_LICENSE_EXPIRY_PAGE = MOSAML_PLUGIN_DIR . 'src' . DIRECTORY_SEPARATOR . 'template' . DIRECTORY_SEPARATOR . 'license-expiry-page.php';
}
