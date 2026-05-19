<?php
/**
 * Tabs for the plugin.
 *
 * @package miniorange-saml-20-single-sign-on
 */

namespace MOSAML\SRC\Constant;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Tabs for the plugin.
 *
 * @package miniorange-saml-20-single-sign-on
 */
class Constants {

	/**
	 * Logical schema revision (mirrors latest semver migration; used in export meta and legacy option).
	 *
	 * @var string
	 */
	const DB_VERSION = '1.0.1';

	/**
	 * Debug log constant.
	 *
	 * @var string
	 */
	const DEBUG_LOG_CONSTANT = 'MOSAML_DEBUG_LOG';

	/**
	 * Tabs for the plugin.
	 *
	 * @var array
	 */
	const TABS = array(
		'sp_metadata'              => 'Service Provider Metadata',
		'sp_setup'                 => 'IDP Configuration',
		'attribute_role_mapping'   => 'Attribute/Role Mapping',
		'sso_redirection_settings' => 'Redirection & SSO Links',
		'advanced_settings'        => 'Advance Settings',
		'custom_certificate'       => 'Manage Certificate',
		'account_settings'         => 'Account Settings',
		'addons'                   => 'Addons',
	);

	/**
	 * Tabs for the multiple environments page.
	 *
	 * @var array
	 */
	const MULTIPLE_ENVIRONMENTS_TABS = array(
		'manage_multiple_environments' => 'Manage Multiple Environments',
	);

	/**
	 * Tabs for the troubleshoot page.
	 *
	 * @var array
	 */
	const TROUBLESHOOT_TABS = array(
		'debug_logger' => 'Debug Logger',
		'error_codes'  => 'Error Codes',
	);

	/**
	 * Admin page slugs for the plugin.
	 *
	 * @var array
	 */
	const ADMIN_PAGE_SLUGS = array(
		'settings'             => 'mo_saml_settings',
		'multiple_environment' => 'mosaml-multiple-environment',
		'troubleshoot'         => 'mosaml-troubleshoot',
	);

	/**
	 * Version hierarchy.
	 *
	 * @var array
	 */
	const VERSION_HIERARCHY = array(
		1 => 'BASE',
		2 => 'STANDARD',
		3 => 'PREMIUM',
		4 => 'ENTERPRISE',
	);

	/**
	 * Version number based on the version hierarchy.
	 *
	 * @var array
	 */
	const VERSION_NUMBER = array(
		1 => '6.0.0',
		2 => '17.0.2',
		3 => '13.0.0',
		4 => '26.0.0',
	);

	const REQUIRED_EXTENSIONS = array(
		'dom',
		'curl',
		'openssl',
	);

	const SP_ENTITY_ID = '/wp-content/plugins/miniorange-saml-20-single-sign-on/';

	const ROLE_MAPPING_ADVANCED_SETTINGS_DOC_URL = 'https://developers.miniorange.com/docs/saml/wordpress/Attribute-Rolemapping-Version12.2.0#Advanced-Settings';

	const DEFAULT_ORGANIZATION_DETAILS = array(
		'name'  => 'miniOrange',
		'email' => 'info@xecurify.com',
		'url'   => 'https://www.miniorange.com',
	);

	/**
	 * Error codes URL.
	 *
	 * @var string
	 */
	const ERROR_CODES_URL = 'https://developers.miniorange.com/docs/saml/wordpress/error-codes';

	const ATTRIBUTE_MAPPING_DOC_URL = 'https://developers.miniorange.com/docs/saml/wordpress/Attribute-Rolemapping-Version12.2.0#Attribute-mapping';

	/**
	 * Pricing page URL.
	 *
	 * @var string
	 */
	const PRICING_PAGE_URL = 'https://plugins.miniorange.com/wordpress-single-sign-on-sso#pricing';

	/**
	 * Documentation URL.
	 *
	 * @var string
	 */
	const DOCUMENTATION_URL = 'https://developers.miniorange.com/docs/saml/wordpress/overview';

	const UPGRADE_FAQ = 'https://faq.miniorange.com/knowledgebase/how-to-get-the-latest-version-of-the-plugin/';

	/**
	 * FAQ URL.
	 *
	 * @var string
	 */
	const FAQ_URL = 'https://faq.miniorange.com/kb/saml-single-sign-on/';

	/**
	 * Renewal FAQ URL.
	 *
	 * @var string
	 */
	const RENEWAL_FAQ_URL = 'https://faq.miniorange.com/knowledgebase/how-can-i-renew-my-wordpress-plugin-license';

	/**
	 * Plugin name.
	 *
	 * @var string
	 */
	const PLUGIN_NAME = 'miniorange-saml-20-single-sign-on';

	/**
	 * Role Mapping Documentation URL.
	 *
	 * @var string
	 */
	const ROLE_MAPPING_DOC_URL = 'https://developers.miniorange.com/docs/saml/wordpress/Attribute-Rolemapping-Version12.2.0#New-Role-Mapping';

	/**
	 * SSO Redirection Settings Documentation URL.
	 *
	 * @var string
	 */
	const SSO_REDIRECTION_SETTINGS_DOC_URL = 'https://developers.miniorange.com/docs/saml/wordpress/Redirection-SSO';

	/**
	 * SSO Links & Buttons Documentation URL.
	 *
	 * @var string
	 */
	const SSO_LINKS_DOC_URL = 'https://developers.miniorange.com/docs/saml/wordpress/Redirection-SSO#Login-button';

	/**
	 * Custom Messages Documentation URL.
	 *
	 * @var string
	 */
	const CUSTOM_MESSAGES_DOC_URL = 'https://developers.miniorange.com/docs/saml/wordpress/Custom-Message';

	/**
	 * Multiple Environments Documentation URL.
	 *
	 * @var string
	 */
	const MULTIPLE_ENVIRONMENTS_DOC_URL = 'https://plugins.miniorange.com/wordpress-migration-in-multiple-environments';

	/**
	 * Multiple Environments YouTube Video URL.
	 *
	 * @var string
	 */
	const MULTIPLE_ENVIRONMENTS_VIDEO_URL = 'https://www.youtube.com/watch?v=j300TWjieBc&feature=emb_imp_woyt';

	/**
	 * IDP guides details.
	 *
	 * @var array
	 */
	const IDP_GUIDES = array(
		'ADFS'           => array( 'adfs', 'saml-single-sign-on-sso-wordpress-using-adfs' ),
		'Azure AD'       => array( 'azure-ad', 'saml-single-sign-on-sso-wordpress-using-azure-ad' ),
		'Azure B2C'      => array( 'azure-b2c', 'saml-single-sign-on-sso-wordpress-using-azure-b2c' ),
		'Okta'           => array( 'okta', 'saml-single-sign-on-sso-wordpress-using-okta' ),
		'Keycloak'       => array( 'jboss-keycloak', 'saml-single-sign-on-sso-wordpress-using-jboss-keycloak' ),
		'Google Apps'    => array( 'google-apps', 'saml-single-sign-on-sso-wordpress-using-google-apps' ),
		'Windows SSO'    => array( 'windows', 'saml-single-sign-on-sso-wordpress-using-adfs' ),
		'SalesForce'     => array( 'salesforce', 'saml-single-sign-on-sso-wordpress-using-salesforce' ),
		'WordPress'      => array( 'wordpress', 'saml-single-sign-on-sso-between-two-wordpress-sites' ),
		'Office 365'     => array( 'office365', 'wordpress-office-365-single-sign-on-sso-login' ),
		'Auth0'          => array( 'auth0', 'saml-single-sign-on-sso-wordpress-using-auth0' ),
		'MiniOrange'     => array( 'miniorange', 'saml-single-sign-on-sso-wordpress-using-miniorange' ),
		'Community'      => array( 'salesforce', 'saml-single-sign-on-sso-wordpress-using-salesforce community' ),
		'Classlink'      => array( 'classlink', 'saml-single-sign-on-sso-login-wordpress-using-classlink' ),
		'OneLogin'       => array( 'onelogin', 'saml-single-sign-on-sso-wordpress-using-onelogin' ),
		'Centrify'       => array( 'centrify', 'saml-single-sign-on-sso-wordpress-using-centrify' ),
		'PingFederate'   => array( 'pingfederate', 'saml-single-sign-on-sso-wordpress-using-pingfederate' ),
		'Shibboleth 2'   => array( 'shibboleth2', 'saml-single-sign-on-sso-wordpress-using-shibboleth2' ),
		'Shibboleth 3'   => array( 'shibboleth3', 'saml-single-sign-on-sso-wordpress-using-shibboleth3' ),
		'AbsorbLMS'      => array( 'absorb-lms', 'saml-single-sign-on-sso-wordpress-using-absorb-lms' ),
		'Gluu Server'    => array( 'gluu-server', 'saml-single-sign-on-sso-wordpress-using-gluu-server' ),
		'JumpCloud'      => array( 'jumpcloud', 'saml-single-sign-on-sso-wordpress-using-jumpcloud' ),
		'IdentityServer' => array( 'identityserver4', 'saml-single-sign-on-sso-wordpress-using-identityserver4' ),
		'Degreed'        => array( 'degreed', 'saml-single-sign-on-sso-wordpress-using-degreed' ),
		'CyberArk'       => array( 'cyberark', 'saml-single-sign-on-sso-for-wordpress-using-cyberark' ),
		'Duo'            => array( 'duo', 'saml-single-sign-on-sso-wordpress-using-duo' ),
		'FusionAuth'     => array( 'fusionauth', 'saml-single-sign-on-sso-wordpress-using-fusionauth' ),
		'SecureAuth'     => array( 'secureauth', 'saml-single-sign-on-sso-wordpress-using-secureauth' ),
		'NetIQ'          => array( 'netiq', 'saml-single-sign-on-sso-wordpress-using-netiq' ),
		'Fonteva'        => array( 'fonteva', 'saml-single-sign-on-sso-wordpress-using-fonteva' ),
		'SURFconext'     => array( 'surfconext', 'surfconext-saml-single-sign-on-sso-in-wordpress' ),
		'PhenixID'       => array( 'phenixid', 'phenixid-saml-single-sign-on-sso-login-wordpresss' ),
		'Authanvil'      => array( 'authanvil', 'saml-single-sign-on-sso-wordpress-using-authanvil' ),
		'Bitium'         => array( 'bitium', 'saml-single-sign-on-sso-wordpress-using-bitium' ),
		'CA Identity'    => array( 'ca-identity', 'saml-single-sign-on-sso-wordpress-using-ca-identity' ),
		'OpenAM'         => array( 'openam', 'saml-single-sign-on-sso-wordpress-using-open-am' ),
		'Oracle'         => array( 'oracle-enterprise-manager', 'saml-single-sign-on-sso-wordpress-using-oracle-enterprise-manager' ),
		'PingOne'        => array( 'pingone', 'saml-single-sign-on-sso-wordpress-using-pingone' ),
		'RSA SecureID'   => array( 'rsa-secureid', 'saml-single-sign-on-sso-wordpress-using-rsa-secureid' ),
		'SimpleSAMLphp'  => array( 'simplesaml', 'saml-single-sign-on-sso-wordpress-using-simplesaml' ),
		'WSO2'           => array( 'wso2', 'saml-single-sign-on-sso-wordpress-using-wso2' ),
		'Custom IDP'     => array( 'custom-idp', 'saml-single-sign-on-sso-wordpress-using-custom-idp' ),
	);

	/**
	 * IDP videos details.
	 *
	 * @var array
	 */
	const IDP_VIDEOS = array(
		'azure-ad'       => 'eHen4aiflFU',
		'adfs'           => 'rLBHbRbrY5E',
		'okta'           => 'YHE8iYojUqM',
		'salesforce'     => 'LRQrmgr255Q',
		'google-apps'    => '5BwzEjgZiu4',
		'onelogin'       => '_Hsot_RG9YY',
		'miniorange'     => 'eamf9s6JpbA',
		'jboss-keycloak' => 'Io6x1fTNWHI',
		'auth0'          => '54pz6m5h9mk',
		'custom-idp'     => 'gilfhNFYsgc',
	);

	/**
	 * IDP status.
	 *
	 * @var array
	 */
	const IDP_STATUS = array(
		'active'   => 'Active',
		'inactive' => 'Inactive',
	);

	/**
	 * IDP bulk actions.
	 *
	 * @var array
	 */
	const IDP_BULK_ACTIONS = array(
		'active'   => 'Activate',
		'inactive' => 'Deactivate',
		'delete'   => 'Delete',
	);

	/**
	 * NameID formats.
	 *
	 * @var array
	 */
	const NAMEID_FORMATS = array(
		'unspecified'  => 'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified',
		'emailAddress' => 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
		'transient'    => 'urn:oasis:names:tc:SAML:2.0:nameid-format:transient',
		'persistent'   => 'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent',
	);

	const SP_PRIVATE_KEY_FILE_NAME = 'miniorange_sp_priv.key';

	const SP_CERT_FILE_NAME = 'miniorange_sp_certificate.crt';

	const NEW_SP_CERT_FILE_NAME        = 'miniorange_sp_certificate_new.crt';
	const NEW_SP_PRIVATE_KEY_FILE_NAME = 'miniorange_sp_priv_new.key';

	const METADATA_URL = '/?option=mosaml_metadata';

	/**
	 * Error message displayed when user creation is disabled.
	 *
	 * @var string
	 */
	const ACCOUNT_CREATION_DISABLED_MSG = 'We could not sign you in. Please contact your Administrator.';

	/**
	 * Error message displayed when a user's domain is restricted.
	 *
	 * @var string
	 */
	const RESTRICTED_DOMAIN_ERROR_MSG = 'You are not allowed to login. Please contact your Administrator.';

	/**
	 * Default IDP name for the plugin.
	 *
	 * @var string
	 */
	const DEFAULT_IDP_NAME = 'All IDPs';

	/**
	 * Default blog ID for the plugin.
	 *
	 * @var int
	 */
	const DEFAULT_BLOG_ID = 0;

	/**
	 * Cron hook for metadata sync.
	 *
	 * @var string
	 */
	const METADATA_SYNC_CRON_HOOK = 'metadata_sync_cron_action';

	/**
	 * Plugin prefix.
	 *
	 * @var string
	 */
	const PLUGIN_PREFIX = 'mosaml_';

	/**
	 * Database table names.
	 *
	 * @var array
	 */
	const DATABASE_TABLE_NAMES = array(
		'environments'      => self::PLUGIN_PREFIX . 'environments',
		'idp_details'       => self::PLUGIN_PREFIX . 'idp_details',
		'sp_metadata'       => self::PLUGIN_PREFIX . 'sp_metadata',
		'subsites'          => self::PLUGIN_PREFIX . 'subsites',
		'attribute_mapping' => self::PLUGIN_PREFIX . 'attribute_mapping',
		'sso_settings'      => self::PLUGIN_PREFIX . 'sso_settings',
		'role_mapping'      => self::PLUGIN_PREFIX . 'role_mapping',
	);

	/**
	 * WordPress option name for keep settings on deletion.
	 *
	 * @var string
	 */
	const KEEP_SETTINGS_OPTION_NAME = 'mosaml_keep_settings_on_deletion';

	/**
	 * WordPress option name for sending plugin configuration with support queries.
	 *
	 * @var string
	 */
	const SEND_PLUGIN_CONFIG_OPTION_NAME = 'mosaml_send_plugin_config';

	/**
	 * WordPress option name for database schema version (semver from database/migrations/*.sql).
	 *
	 * @var string
	 */
	const DB_VERSION_OPTION_NAME = 'mosaml_sp_db_version';

	/**
	 * WordPress option name for debug log file path.
	 *
	 * @var string
	 */
	const DEBUG_LOG_FILE_PATH_OPTION_NAME = 'mosaml_debug_log_file_path';

	/**
	 * WordPress option name for Multiple Environment.
	 *
	 * @var string
	 */
	const ENABLE_MULTIPLE_ENVIRONMENTS_OPTION_NAME = 'mosaml_enable_multiple_environments';

	/**
	 * WordPress option name for admin notice message.
	 *
	 * @var string
	 */
	const ADMIN_NOTICE_MESSAGE_OPTION_NAME = 'mosaml_message';

	/**
	 * WordPress option name for tried to update database.
	 *
	 * @var string
	 */
	const DATABASE_UPDATE_STATUS = 'mosaml_database_update_status';

	/**
	 * WordPress option name for dismissed database update required.
	 *
	 * @var string
	 */
	const DISMISSED_DATABASE_UPDATE_REQUIRED_NOTICE_OPTION_NAME = 'mosaml_dismissed_database_update_required_notice';

	/**
	 * WordPress option name for database setup required.
	 *
	 * @var string
	 */
	const DATABASE_SETUP_COMPLETED_OPTION_NAME = 'mosaml_database_setup_completed';

	/**
	 * WordPress option name for enabling plugin backup on upgrade.
	 *
	 * @var string
	 */
	const ENABLE_BACKUP_SETTINGS = 'mo_saml_enable_backup_settings';

	/**
	 * WordPress option name for migration status.
	 *
	 * @var string
	 */
	const MIGRATION_STATUS = 'mosaml_migration_status';

	/**
	 * Custom SSO Error Message addon slug.
	 *
	 * @var string
	 */
	const CUSTOM_SSO_ERROR_MESSAGE_ADDON_SLUG = 'miniorange-custom-sso-error-message/custom-sso-error-message.php';
}
