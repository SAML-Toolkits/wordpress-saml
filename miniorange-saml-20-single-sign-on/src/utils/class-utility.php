<?php
/**
 * Utility class.
 *
 * This class contains utility functions for the plugin.
 *
 * @package miniorange-saml-20-single-sign-on/utils
 */

namespace MOSAML\SRC\Utils;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\SRC\Constant\Constants;
use MOSAML\SRC\Constant\URL_Constants;
use MOSAML\SRC\Exception\DOM_Extension_Disabled_Exception;
use MOSAML\SRC\Exception\CURL_Extension_Disabled_Exception;
use MOSAML\SRC\Exception\OpenSSL_Extension_Disabled_Exception;
use MOSAML\SRC\Exception\Metadata_Parse_Exception;
use MOSAML\SRC\Exception\Metadata_Validation_Exception;
use MOSAML\SRC\Handler\Import_Export\Import_Export_Config_Handler;
use MOSAML\SRC\Constant\Plugin_Options;
use MOSAML\SRC\Classes\Mo_Customer;
use MOSAML\SRC\Library\License\License_Utility;
use MOSAML\SRC\Constant\Error_Codes_Enums;
use MOSAML\LicenseLibrary\Utils\Mo_License_Service_Utility;
use DOMDocument;
use DOMXPath;
use Exception;
use ReflectionClass;

/**
 * Utility class.
 *
 * This class contains utility functions for the plugin.
 */
class Utility {

	/**
	 * Gets the current version of the plugin.
	 *
	 * @return int The current version of the plugin.
	 */
	public static function get_current_version() {
		$base_dir = MOSAML_PLUGIN_DIR . 'module' . DIRECTORY_SEPARATOR;

		$versions = array(
			4 => array( 'enterprise', 'premium', 'standard' ),
			3 => array( 'premium', 'standard' ),
			2 => array( 'standard' ),
		);

		foreach ( $versions as $version => $dirs ) {
			$all_exist = array_reduce(
				$dirs,
				function ( $carry, $dir ) use ( $base_dir ) {
					return $carry && is_dir( $base_dir . $dir );
				},
				true
			);
			if ( $all_exist ) {
				return $version;
			}
		}
		return 1;
	}

	/**
	 * Get the license plans.
	 *
	 * @return array The license plans.
	 */
	public static function get_license_plans() {
		$version = self::get_current_version();

		$license_mapping = array(
			4 => array(
				'LICENSE_TYPE'      => 'WP_SAML_SP_MULTIPLE_IDP_PLUGIN',
				'LICENSE_PLAN_NAME' => 'wp_saml_sso_multiple_idp_plan',
			),
			3 => array(
				'LICENSE_TYPE'      => 'WP_SAML_SP_PLUGIN',
				'LICENSE_PLAN_NAME' => 'wp_saml_sso_basic_plan',
			),
			2 => array(
				'LICENSE_TYPE'      => 'WP_SAML_SP_STANDARD_PLUGIN',
				'LICENSE_PLAN_NAME' => 'wp_saml_sso_standard_plan',
			),
			1 => array(
				'LICENSE_TYPE'      => 'false',
				'LICENSE_PLAN_NAME' => 'false',
			),
		);

		return isset( $license_mapping[ $version ] ) ? $license_mapping[ $version ] : $license_mapping[1];
	}

	/**
	 * Gets the renewal FAQ URL with version-specific UTM parameters.
	 *
	 * @return string The renewal FAQ URL.
	 */
	public static function get_renewal_faq_url() {
		$utm_map = array(
			2 => array(
				'utm_source' => 'samlspstandard',
				'utm_id'     => '3',
			),
			3 => array(
				'utm_source' => 'samlsppremium',
				'utm_id'     => '1',
			),
			4 => array(
				'utm_source' => 'samlspmultipleidp',
				'utm_id'     => '2',
			),
		);
		$version = defined( 'MOSAML_VERSION' ) ? MOSAML_VERSION : 2;
		$utm     = isset( $utm_map[ $version ] ) ? $utm_map[ $version ] : $utm_map[2];
		return add_query_arg(
			array(
				'utm_source'   => $utm['utm_source'],
				'utm_medium'   => 'plugin',
				'utm_campaign' => 'renewal-faq',
				'utm_id'       => $utm['utm_id'],
			),
			Constants::RENEWAL_FAQ_URL
		);
	}

	/**
	 * Sanitizes the post data.
	 *
	 * @param string $key The key to sanitize.
	 * @param bool   $return_array Whether to return the data as an array.
	 * @param string $sanitze_func The function to use for sanitization.
	 * @return string|array The sanitized data.
	 */
	public static function sanitize_post_data( $key, $return_array = false, $sanitze_func = 'sanitize_text_field' ) {
		// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized, WordPress.Security.NonceVerification.Missing -- This function handles sanitization and the nonce is already checked in the form submission.
		$value = isset( $_POST[ $key ] ) ? wp_unslash( $_POST[ $key ] ) : null;

		if ( null === $value ) {
			return $return_array ? array() : '';
		}

		return is_array( $value ) ? array_map( $sanitze_func, $value ) : call_user_func( $sanitze_func, $value );
	}

	/**
	 * Sanitizes the get data.
	 *
	 * @param string $key The key to sanitize.
	 * @param bool   $return_array Whether to return the data as an array.
	 * @return string|array The sanitized data.
	 */
	public static function sanitize_get_data( $key, $return_array = false ) {
		// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized, WordPress.Security.NonceVerification.Recommended -- This function handles sanitization and the nonce is already checked in the form submission.
		$value = isset( $_GET[ $key ] ) ? wp_unslash( $_GET[ $key ] ) : null;

		if ( null === $value ) {
			return $return_array ? array() : '';
		}

		return is_array( $value ) ? array_map( 'sanitize_text_field', $value ) : sanitize_text_field( $value );
	}

	/**
	 * Get file data from $_FILES superglobal.
	 *
	 * @param string $key The file input name.
	 * @return array|string The file data or empty string if not found.
	 */
	public static function get_global_file_data( $key ) {
		// phpcs:ignore WordPress.Security.NonceVerification.Missing, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
		return isset( $_FILES[ $key ] ) ? $_FILES[ $key ] : '';
	}

	/**
	 * Starts the session if not started already.
	 *
	 * @return void
	 */
	public static function start_session() {
		if ( session_status() === PHP_SESSION_NONE ) {
			session_start();
		}
	}

	/**
	 * Start output buffering to prevent headers already sent warnings.
	 *
	 * @return void
	 */
	public static function start_output_buffering() {
		if ( ! ob_get_level() ) {
			ob_start();
		}
	}

	/**
	 * Clean output buffer to prevent headers already sent warnings.
	 *
	 * @return void
	 */
	public static function clean_output_buffer() {
		if ( ob_get_level() ) {
			ob_end_clean();
		}
	}

	/**
	 * Checks if the required PHP extensions are installed.
	 *
	 * @return array List of required extension names that are not loaded.
	 */
	public static function check_required_extensions() {
		return self::check_is_extension_installed( Constants::REQUIRED_EXTENSIONS );
	}

	/**
	 * Checks whether each of the given PHP extensions is loaded.
	 *
	 * @param array $extensions_to_check List of extension names to check (e.g. 'dom', 'curl', 'openssl').
	 * @return array List of extension names that are not loaded.
	 */
	public static function check_is_extension_installed( $extensions_to_check ) {
		if ( empty( $extensions_to_check ) || ! is_array( $extensions_to_check ) ) {
			return array();
		}

		$missing = array();
		foreach ( $extensions_to_check as $ext ) {
			if ( ! extension_loaded( $ext ) ) {
				$missing[] = $ext;
			}
		}

		return $missing;
	}

	/**
	 * Returns an exception instance for the given missing extension name.
	 *
	 * @param string $extension_name Extension name (e.g. 'dom', 'curl', 'openssl').
	 * @return DOM_Extension_Disabled_Exception|CURL_Extension_Disabled_Exception|OpenSSL_Extension_Disabled_Exception|null
	 */
	public static function create_extension_disabled_exception( $extension_name ) {
		switch ( $extension_name ) {
			case 'dom':
				return new DOM_Extension_Disabled_Exception( 'DOM extension is not installed.' );
			case 'curl':
				return new CURL_Extension_Disabled_Exception( 'cURL extension is not installed.' );
			case 'openssl':
				return new OpenSSL_Extension_Disabled_Exception( 'OpenSSL extension is not installed.' );
			default:
				return null;
		}
	}

	/**
	 * Function to delete/unset cookies set by plugin.
	 *
	 * @return void
	 */
	public static function delete_plugin_session_and_cookies() {
		$is_secure = self::get_secure_cookie_attribute();
		if ( isset( $_SESSION['mo_guest_login']['nameID'] ) ) {
			unset( $_SESSION['mo_guest_login'] );
		} else {
			unset( $_SESSION['mo_saml'] );
			unset( $_COOKIE['logged_in_with_idp'] );
			unset( $_COOKIE['logged_in_idp_id'] );
			unset( $_COOKIE['nameID'] );
			unset( $_COOKIE['sessionIndex'] );
		}

		setcookie( 'nameID', '', time() - 3600, '/', '', $is_secure, true );
		setcookie( 'sessionIndex', '', time() - 3600, '/', '', $is_secure, true );
		setcookie( 'logged_in_with_idp', '', time() - 3600, '/', '', $is_secure, true );
	}

	/**
	 * Get the secure cookie attribute.
	 *
	 * @return bool
	 */
	public static function get_secure_cookie_attribute() {

		$is_secure = is_ssl() && 'https' === wp_parse_url( home_url(), PHP_URL_SCHEME );

		/**
		 * Filter to change the default behaviour for setting secure cookies.
		 *
		 * @param bool $is_secure secure attribute of cookie.
		 */
		return apply_filters( 'mosaml_set_secure_cookie_attribute_internal', $is_secure );
	}


	/**
	 * Run an XPath query on an XML node.
	 *
	 * This function helps search for specific elements in an XML document using an XPath query.
	 * It automatically sets up the required SAML and XML namespaces (like saml, saml_metadata, ds, etc.)
	 * so the query can find elements correctly, even if they use those prefixes.
	 *
	 * It returns all matching nodes as an array.
	 *
	 * @param \DOMNode $dom_node  The starting point in the XML document to search from.
	 * @param string   $xpath_query The XPath query string to run.
	 * @return array An array of matched DOM nodes.
	 */
	public static function xp_query( $dom_node, $xpath_query ) {
		static $xp_cache = null;

		if ( $dom_node instanceof DOMDocument ) {
			$doc = $dom_node;
		} else {
			// phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- DOM API property.
			$doc = $dom_node->ownerDocument;
		}

		if ( null === $xp_cache || ! $xp_cache->document->isSameNode( $doc ) ) {
			$xp_cache = new DOMXPath( $doc );
			$xp_cache->registerNamespace( 'soap-env', 'http://schemas.xmlsoap.org/soap/envelope/' );
			$xp_cache->registerNamespace( 'saml_protocol', 'urn:oasis:names:tc:SAML:2.0:protocol' );
			$xp_cache->registerNamespace( 'saml_assertion', 'urn:oasis:names:tc:SAML:2.0:assertion' );
			$xp_cache->registerNamespace( 'saml_metadata', 'urn:oasis:names:tc:SAML:2.0:metadata' );
			$xp_cache->registerNamespace( 'ds', 'http://www.w3.org/2000/09/xmldsig#' );
			$xp_cache->registerNamespace( 'xenc', 'http://www.w3.org/2001/04/xmlenc#' );
			$xp_cache->registerNamespace( 'mdui', 'urn:oasis:names:tc:SAML:metadata:ui' );
		}

		$results = $xp_cache->query( $xpath_query, $dom_node );
		$ret     = array();
		for ( $i = 0; $i < $results->length; $i++ ) {
			$ret[ $i ] = $results->item( $i );
		}

		return $ret;
	}

	/**
	 * Make a remote HTTP call using WordPress HTTP API
	 *
	 * @param string $url The URL to call.
	 * @param array  $args Additional arguments for the request.
	 * @return array|WP_Error Response array or WP_Error on failure.
	 */
	public static function wp_remote_call( $url, $args = array() ) {
		$defaults = array(
			'timeout'     => 30,
			'redirection' => 5,
			'httpversion' => '1.0',
			'user-agent'  => 'WordPress/' . get_bloginfo( 'version' ) . '; ' . get_bloginfo( 'url' ),
			'blocking'    => true,
			'headers'     => array(),
			'cookies'     => array(),
			'body'        => null,
			'compress'    => false,
			'decompress'  => true,
			'sslverify'   => true,
			'stream'      => false,
			'filename'    => null,
		);

		$args = wp_parse_args( $args, $defaults );

		return wp_remote_get( $url, $args );
	}

	/**
	 * Safely load XML string with comprehensive security measures
	 *
	 * This function hardens loadXML function to parse XML safely by:
	 * - Disabling loading/expansion of external and internal entities
	 * - Preventing XXE (XML External Entity) attacks
	 * - Blocking DTD (Document Type Definition) processing
	 * - Custom error handling
	 *
	 * @param string $xml_string The XML string to load.
	 * @param string $error_code Optional error code for logging/identification.
	 * @param bool   $log_error Whether to log errors.
	 * @return DOMDocument DOMDocument on success.
	 * @throws DOM_Extension_Disabled_Exception If DOMDocument class is not available.
	 * @throws Metadata_Parse_Exception If XML parsing fails.
	 * @throws Metadata_Validation_Exception If XML validation fails.
	 */
	public static function safe_load_xml( $xml_string, $error_code = '', $log_error = false ) {
		unset( $error_code, $log_error );
		if ( ! class_exists( 'DOMDocument' ) ) {
			throw new DOM_Extension_Disabled_Exception( 'DOMDocument class is not available. Please ensure the DOM extension is installed.' );
		}

		if ( empty( $xml_string ) || ! is_string( $xml_string ) ) {
			throw new Metadata_Parse_Exception( 'Empty or invalid XML string provided.' );
		}

		$document = new DOMDocument();
		// phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- DOMDocument API property.
		$document->preserveWhiteSpace = false;
		// phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- DOMDocument API property.
		$document->formatOutput = false;

		$old_use_internal_errors = libxml_use_internal_errors( true );

		libxml_set_external_entity_loader( null );

		// phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_set_error_handler -- Custom error handler for XML parsing.
		$old_error_handler = set_error_handler( array( __CLASS__, 'handle_xml_error' ) );

		try {
			$xml_loaded = $document->loadXML(
				$xml_string,
				LIBXML_NONET | LIBXML_DTDLOAD | LIBXML_DTDATTR | LIBXML_NOENT | LIBXML_NOCDATA
			);

			if ( ! $xml_loaded ) {
				$error_message = 'Failed to parse XML content';
				$errors        = libxml_get_errors();
				if ( ! empty( $errors ) ) {
					$error_details = array();
					foreach ( $errors as $error ) {
						$error_details[] = trim( $error->message );
					}
					$error_message .= ': ' . implode( '; ', $error_details );
				}
				Error_Success_Message::display_error_notice_to_admin( Error_Codes_Enums::$error_codes['WPSAMLERR026'] );
				return false;
			} else {
				$has_dtd = false;
				// phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- DOMDocument API property.
				foreach ( $document->childNodes as $child ) {
					// phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- DOMNode API property.
					if ( XML_DOCUMENT_TYPE_NODE === $child->nodeType ) {
						$has_dtd = true;
						break;
					}
				}

				if ( $has_dtd ) {
					throw new Metadata_Validation_Exception( 'XML contains DTD declarations which are not allowed for security reasons.' );
				} elseif ( self::contains_suspicious_xml_content( $xml_string ) ) {
					throw new Metadata_Validation_Exception( 'XML contains potentially malicious content.' );
				}
			}
		} catch ( Exception $e ) {
			throw new Metadata_Parse_Exception( 'Unexpected error occurred during XML parsing: ' . esc_html( $e->getMessage() ) );
		}

		if ( null !== $old_error_handler ) {
			restore_error_handler();
		}
		libxml_use_internal_errors( $old_use_internal_errors );
		libxml_clear_errors();

		return $document;
	}

	/**
	 * Check for suspicious XML content patterns
	 *
	 * @param string $xml_string The XML string to check.
	 * @return bool True if suspicious content found, false otherwise.
	 */
	private static function contains_suspicious_xml_content( $xml_string ) {
		$suspicious_patterns = array(
			'/<!ENTITY/i',
			'/SYSTEM\s+["\']file:/i',
			'/SYSTEM\s+["\']http/i',
			'/SYSTEM\s+["\']ftp/i',
			'/<!DOCTYPE.*\[/i',
			'/<!DOCTYPE[^>]*\[.*%[a-zA-Z][a-zA-Z0-9_-]*;/is',
		);

		foreach ( $suspicious_patterns as $pattern ) {
			if ( preg_match( $pattern, $xml_string ) ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Function to handle the license calls like verify customer, license etc.
	 *
	 * @param string $method Function to call.
	 * @param string $class_type Variable to identify the class type to call.
	 * @param mixed  $default_return Default return value when call cannot be made.
	 * @param mixed  ...$args Arguments to pass to the method.
	 *
	 * @return mixed|null
	 */
	public static function handle_license_calls( $method, $class_type = 'base', $default_return = null, ...$args ) {

		$class_object = null;

		if ( ( 'library' === $class_type || 'both' === $class_type ) && class_exists( '\MOSAML\SRC\Library\License\License_Utility' ) ) {
			$class_object = new License_Utility();
		} elseif ( class_exists( 'MOSAML\SRC\Classes\Mo_Customer' ) ) {
			$class_object = new Mo_Customer();
		}
		if ( null !== $class_object && method_exists( $class_object, $method ) ) {
			return $class_object->{$method}( ...$args );
		}

		return $default_return;
	}

	/**
	 * Initialize the license library and framework instance.
	 *
	 * @return void
	 */
	public static function initialize_license_library() {
		try {
			Utility::check_is_extension_installed( Constants::REQUIRED_EXTENSIONS );
			self::handle_license_calls( 'initialize_library', 'library' );
			self::handle_license_calls( 'update_framework_instance', 'library' );
		} catch ( DOM_Extension_Disabled_Exception $e ) {
			return;
		} catch ( CURL_Extension_Disabled_Exception $e ) {
			return;
		} catch ( OpenSSL_Extension_Disabled_Exception $e ) {
			return;
		}
	}

	/**
	 * Function to handle the licnese calls like verify customer, license etc.
	 *
	 * @return void
	 */
	public static function contact_us_for_support() {
		if ( ! self::is_extension_installed( 'curl' ) ) {
			Error_Success_Message::show_admin_notice( 'ERROR: PHP cURL extension is not installed or disabled. Query submit failed.' );
			return;
		}

		$email = self::sanitize_post_data( 'mosaml_contact_us_email' );
		$phone = self::sanitize_post_data( 'mosaml_contact_us_phone' );
		$query = self::sanitize_post_data( 'mosaml_contact_us_query' );

		if ( self::sanitize_post_data( Constants::SEND_PLUGIN_CONFIG_OPTION_NAME ) === 'checked' ) {
			$plugin_config      = Import_Export_Config_Handler::prepare_configurations();
			$plugin_config_json = wp_json_encode( $plugin_config );
			if ( ! empty( $plugin_config_json ) ) {
				$query = $query . '<br><br>Plugin Configuration: ' . $plugin_config_json;
			}
			update_option( Constants::SEND_PLUGIN_CONFIG_OPTION_NAME, 'checked' );
		} else {
			delete_option( Constants::SEND_PLUGIN_CONFIG_OPTION_NAME );
		}

		if ( self::mo_saml_check_empty_or_null( array( $email, $query ) ) ) {
			Error_Success_Message::show_admin_notice( 'Please fill up Email and Query fields to submit your query.' );
			return;
		}

		if ( ! filter_var( $email, FILTER_VALIDATE_EMAIL ) ) {
			Error_Success_Message::show_admin_notice( 'Please enter a valid email address.' );
			return;
		}

		$customer = new Mo_Customer();
		$response = $customer->submit_contact_us( $email, $phone, $query );

		if ( $response ) {
			if ( is_wp_error( $response ) || ( is_string( $response ) && stripos( $response, 'Invalid email' ) !== false ) ) {
				Error_Success_Message::show_admin_notice( 'You have entered an invalid email address. Please enter a valid email address to submit your query.', 'ERROR' );
			} else {
				Error_Success_Message::show_admin_notice( 'Your query has been submitted successfully. Our support team will get back to you shortly.', 'SUCCESS' );
			}
		} else {
			Error_Success_Message::show_admin_notice( 'There was an error submitting your query. Please try again later.' );
		}
	}

	/**
	 * Handle XML parsing errors (fallback error handler)
	 *
	 * @param int    $errno Error number.
	 * @param string $errstr Error message.
	 * @return bool Always returns true to prevent default error handling
	 */
	public static function handle_xml_error( $errno, $errstr ) {
		unset( $errno, $errstr );
		return true;
	}

	/**
	 * Function to generate a unique random string for the IDP ID.
	 *
	 * @return string Unique IDP ID
	 */
	public static function generate_idp_id() {
		$letters = 'abcdefghijklmnopqrstuvwxyz';
		$numbers = '0123456789';

		do {
			$shuffled_letters = str_shuffle( $letters );
			$shuffled_numbers = str_shuffle( $numbers );

			$random_letters = substr( $shuffled_letters, 0, 3 );
			$random_numbers = substr( $shuffled_numbers, 0, 3 );

			$random_string = $random_letters . $random_numbers;

			$exists = ! empty( DB_Utils::get_records( Constants::DATABASE_TABLE_NAMES['idp_details'], array( 'idp_id' => $random_string ) ) );

		} while ( $exists );

		return $random_string;
	}

	/**
	 * Check if PHP extension is installed
	 *
	 * @param string $extension Extension name.
	 * @return bool True if installed, false otherwise.
	 */
	public static function is_extension_installed( $extension ) {
		return extension_loaded( $extension );
	}

	/**
	 * Strip scheme (http/https) while comparing environment urls
	 *
	 * @param string $url The URL to parse.
	 * @return string The parsed URL.
	 */
	public static function parse_environment_url( $url ) {
		$url_scheme = wp_parse_url( $url, PHP_URL_SCHEME );
		$url        = str_replace( $url_scheme . '://', '', $url );
		return $url;
	}

		/**
		 * Validates that cURL extension is available.
		 *
		 * @throws CURL_Extension_Disabled_Exception If cURL extension is disabled.
		 */
	public static function validate_curl_extension() {
		if ( ! self::is_extension_installed( 'curl' ) ) {
			throw new CURL_Extension_Disabled_Exception( 'PHP cURL extension is not installed or disabled' );
		}
	}

	/**
	 * Generates Random ID of 21 characters.
	 *
	 * @return string
	 */
	public static function generate_id() {
		return '_' . self::string_to_hex( self::generate_random_bytes( 21 ) );
	}

	/**
	 * Coverts String to Hex.
	 *
	 * @param  string $bytes Contains bytes.
	 * @return string
	 */
	public static function string_to_hex( $bytes ) {
		$ret    = '';
		$length = strlen( $bytes );
		for ( $i = 0; $i < $length; $i++ ) {
			$ret .= sprintf( '%02x', ord( $bytes[ $i ] ) );
		}
		return $ret;
	}

	/**
	 * Generates Random Bytes.
	 *
	 * @param   int $length Length of characters generating Random Bytes.
	 * @return string
	 */
	public static function generate_random_bytes( $length ) {
		self::check_required_extensions();
		return openssl_random_pseudo_bytes( $length );
	}

	/**
	 * Generates time stamp.
	 *
	 * @param  mixed $instant Store current time.
	 * @return Date.
	 */
	public static function generate_time_stamp( $instant = null ) {
		if ( null === $instant ) {
			$instant = time();
		}
		return gmdate( 'Y-m-d\TH:i:s\Z', $instant );
	}

	/**
	 * Get URL of current page.
	 *
	 * @return bool|string
	 */
	public static function get_current_page_url() {

		//phpcs:ignore WordPress.Security.ValidatedSanitizedInput.MissingUnslash -- Don't need to un-slash a possible URL.
		$http_host = isset( $_SERVER['HTTP_HOST'] ) ? esc_url_raw( $_SERVER['HTTP_HOST'] ) : '';
		//phpcs:ignore WordPress.Security.ValidatedSanitizedInput.MissingUnslash -- Don't need to un-slash a possible URL.
		$is_https = ( isset( $_SERVER['HTTPS'] ) && strcasecmp( esc_url_raw( $_SERVER['HTTPS'] ), 'on' ) === 0 );

		if ( filter_var( $http_host, FILTER_VALIDATE_URL ) ) {
			$http_host = wp_parse_url( $http_host, PHP_URL_HOST );
		}

		//phpcs:ignore WordPress.Security.ValidatedSanitizedInput.MissingUnslash -- Don't need to un-slash a URI.
		$request_uri = isset( $_SERVER['REQUEST_URI'] ) ? esc_url_raw( $_SERVER['REQUEST_URI'] ) : '';

		if ( substr( $request_uri, 0, 1 ) === '/' ) {
			$request_uri = substr( $request_uri, 1 );
		}

		if ( strpos( $request_uri, '?option=saml_user_login' ) !== false ) {
			//phpcs:ignore WordPress.Security.ValidatedSanitizedInput.MissingUnslash -- Don't need to un-slash a URI.
			return strtok( esc_url_raw( $_SERVER['REQUEST_URI'] ), '?' );
		}
		return 'http' . ( $is_https ? 's' : '' ) . '://' . $http_host . '/' . $request_uri;
	}

	/**
	 * Checks if the current user is an administrator.
	 *
	 * @return bool True if the current user is an administrator, false otherwise.
	 */
	public static function is_admin_user() {
		return current_user_can( 'manage_options' );
	}

	/**
	 * Get the handler class.
	 *
	 * @param string $handler_name The handler name.
	 * @param bool   $is_module_handler Whether the handler is a module handler.
	 * @param string $sub_folder The sub folder.
	 * @param mixed  ...$args The arguments to pass to the handler.
	 * @return object The handler class.
	 */
	public static function get_handler_object( $handler_name, $is_module_handler = true, $sub_folder = '', ...$args ) {
		$base_namespace = ( $is_module_handler ? 'MOSAML\\Module\\' . ucfirst( strtolower( Constants::VERSION_HIERARCHY[ MOSAML_VERSION ] ) ) : 'MOSAML\\SRC' ) . '\\Handler';
		if ( ! empty( $sub_folder ) ) {
			$base_namespace .= '\\' . trim( $sub_folder, '\\' );
		}
		$class_name    = implode( '_', array_map( 'ucfirst', explode( '_', strtolower( $handler_name ) ) ) ) . '_Handler';
		$handler_class = $base_namespace . '\\' . $class_name;
		return new $handler_class( ...$args );
	}

	/**
	 * Detect configuration type based on Plugin_version
	 *
	 * @param array $config_data Decoded JSON configuration data.
	 * @return string Configuration type (base, standard, premium, enterprise)
	 */
	public static function detect_config_type( $config_data ) {
		if ( isset( $config_data['Version_dependencies']['Plugin_version'] ) ) {
			$version               = $config_data['Version_dependencies']['Plugin_version'];
			$config_plugin_version = (int) explode( '.', $version )[0];

			if ( $config_plugin_version >= 25 ) {
				return 'enterprise';
			} elseif ( $config_plugin_version >= 16 ) {
				return 'standard';
			} elseif ( $config_plugin_version >= 12 ) {
				return 'premium';
			} elseif ( $config_plugin_version >= 5 ) {
				return 'base';
			}
		}

		return '';
	}


	/**
	 * Get user name based on greeting option.
	 *
	 * @param \WP_User $user User object.
	 * @param string   $option Greeting name option.
	 * @return string
	 */
	public static function get_user_name( $user, $option ) {
		switch ( $option ) {
			case 'EMAIL':
				return $user->user_email;
			case 'FNAME':
				return ! empty( $user->first_name ) ? $user->first_name : $user->user_login;
			case 'LNAME':
				return ! empty( $user->last_name ) ? $user->last_name : $user->user_login;
			case 'FNAME_LNAME':
				$first    = ! empty( $user->first_name ) ? $user->first_name : '';
				$last     = ! empty( $user->last_name ) ? $user->last_name : '';
				$fullname = trim( $first . ' ' . $last );
				return ! empty( $fullname ) ? $fullname : $user->user_login;
			case 'LNAME_FNAME':
				$first    = ! empty( $user->first_name ) ? $user->first_name : '';
				$last     = ! empty( $user->last_name ) ? $user->last_name : '';
				$fullname = trim( $last . ' ' . $first );
				return ! empty( $fullname ) ? $fullname : $user->user_login;
			default:
				return $user->user_login;
		}
	}

	/**
	 * Sanitize request data.
	 *
	 * @param string $key The key to sanitize.
	 * @param bool   $return_array Whether to return an array.
	 * @param mixed  $default_value The default value to return if the key is not set.
	 * @return mixed The sanitized value.
	 */
	public static function sanitize_request_data( $key, $return_array = false, $default_value = null ) {
		//phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized, WordPress.Security.NonceVerification.Recommended -- Verification is done in the same function and nonce is not required.
		$value = isset( $_REQUEST[ $key ] ) ? wp_unslash( $_REQUEST[ $key ] ) : '';
		if ( empty( $value ) ) {
			return ! is_null( $default_value ) ? $default_value : ( $return_array ? array() : '' );
		}
		return is_array( $value ) ? array_map( 'sanitize_text_field', $value ) : sanitize_text_field( $value );
	}

	/**
	 * Sanitize SAML RelayState from the request.
	 *
	 * Login requests send RelayState with {@see rawurlencode()} (see SAML request handler).
	 * The ACS may return it still encoded; {@see sanitize_text_field()} also strips %XX,
	 * so we unslash, decode with rawurldecode (pair to rawurlencode), then validate UTF-8.
	 *
	 * @return string Empty string if RelayState is missing or not a string.
	 */
	public static function sanitize_relay_state_request() {
		// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- RelayState is unslashed and sanitized end-to-end here; avoid sanitize_text_field() (strips %XX before rawurldecode).
		$value = isset( $_REQUEST['RelayState'] ) ? wp_unslash( $_REQUEST['RelayState'] ) : '';
		if ( is_array( $value ) ) {
			$value = reset( $value );
		}
		if ( ! is_string( $value ) ) {
			return '';
		}
		$value = str_replace( "\0", '', $value );
		// phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.urlencode_urldecode -- Intentional pair to rawurlencode() on SAML login RelayState.
		$value = rawurldecode( $value );

		return wp_check_invalid_utf8( $value, true );
	}

	/**
	 * Converts Date to Timestamp.
	 *
	 * @param  mixed $time Contains time value.
	 * @return string
	 * @throws Metadata_Parse_Exception If the timestamp is invalid.
	 */
	public static function convert_date_time_to_timestamp( $time ) {
		$matches = array();

		// We use a very strict regex to parse the timestamp.
		$regex = '/^(\\d\\d\\d\\d)-(\\d\\d)-(\\d\\d)T(\\d\\d):(\\d\\d):(\\d\\d)(?:\\.\\d+)?Z$/D';
		if ( preg_match( $regex, $time, $matches ) === 0 ) {
			throw new Metadata_Parse_Exception( 'Invalid SAML2 timestamp passed to xsDateTimeToTimestamp: ' . esc_html( $time ) );
		}

		// Extract the different components of the time from the  matches in the regex.
		// intval will ignore leading zeroes in the string.
		$year   = intval( $matches[1] );
		$month  = intval( $matches[2] );
		$day    = intval( $matches[3] );
		$hour   = intval( $matches[4] );
		$minute = intval( $matches[5] );
		$second = intval( $matches[6] );

		// We use gmmktime because the timestamp will always be given
		// in UTC.
		$ts = gmmktime( $hour, $minute, $second, $month, $day, $year );

		return $ts;
	}

	/**
	 * Get the tab URL.
	 *
	 * @param string $tab The tab key to append to the URL.
	 * @param string $sub_tab The sub tab key to append to the URL.
	 * @param string $idp_id The IDP ID to append to the URL.
	 * @return string The tab URL.
	 */
	public static function get_tab_url( $tab, $sub_tab = '', $idp_id = '' ) {
		$url = add_query_arg(
			array(
				'page' => 'mo_saml_settings',
				'tab'  => $tab,
			),
			admin_url( 'admin.php' )
		);
		if ( ! empty( $sub_tab ) ) {
			add_query_arg(
				array(
					'subtab' => $sub_tab,
				),
				$url
			);
		}
		if ( ! empty( $idp_id ) ) {
			add_query_arg(
				array(
					'idp' => $idp_id,
				),
				$url
			);
		}
		return $url;
	}

	/**
	 * Get sync interval options for metadata sync dropdowns.
	 *
	 * @param bool $include_select Include a default empty "Select interval" option.
	 * @return array<string,string> Keyed array of interval => label.
	 */
	public static function get_sync_interval_options( $include_select = false ) {
		$options = array(
			'hourly'     => 'Hourly',
			'twicedaily' => 'Twice Daily',
			'daily'      => 'Daily',
			'weekly'     => 'Weekly',
			'monthly'    => 'Monthly',
		);

		if ( $include_select ) {
			$options = array( '' => 'Select interval' ) + $options;
		}

		return $options;
	}

	/**
	 * Get the DTO object.
	 *
	 * @param string $class_name The class name.
	 * @return object The DTO object.
	 */
	public static function get_dto_object( $class_name ) {
		$base_namespace = 'MOSAML\\SRC\\DTO';
		$class_name     = implode( '_', array_map( 'ucfirst', explode( '_', strtolower( $class_name ) ) ) ) . '_DTO';
		$class_path     = $base_namespace . '\\' . $class_name;
		return new $class_path();
	}

	/**
	 * Get content from URL.
	 *
	 * @param string $url The URL to fetch content from.
	 * @return string|false Content on success, false on failure.
	 */
	public static function get_content_from_url( $url ) {
		if ( empty( $url ) || ! is_string( $url ) ) {
			return false;
		}

		$response = wp_remote_get( $url );

		if ( is_wp_error( $response ) ) {
			return false;
		}

		$content = wp_remote_retrieve_body( $response );
		return ! empty( $content ) ? $content : false;
	}

	/**
	 * Get content from uploaded file.
	 *
	 * @param array $file The file data array with 'tmp_name' key.
	 * @return string|false Content on success, false on failure.
	 */
	public static function get_content_from_file( $file ) {
		if ( empty( $file ) || ! is_array( $file ) || empty( $file['tmp_name'] ) ) {
			return false;
		}

		$tmp_name = $file['tmp_name'];
		if ( ! is_string( $tmp_name ) || ! is_readable( $tmp_name ) ) {
			return false;
		}

		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- Reading an uploaded local file.
		$content = file_get_contents( $tmp_name );
		return false !== $content ? $content : false;
	}

	/**
	 * Get the test config URL.
	 *
	 * @param string $idp_id The IDP ID.
	 * @return string The test config URL.
	 */
	public static function get_test_config_url( $idp_id ) {
		return add_query_arg(
			array(
				'option'   => Plugin_Options::SAML_REQUEST_OPTION['TEST_CONFIG'],
				'idp'      => $idp_id,
				'_wpnonce' => wp_create_nonce( Plugin_Options::SAML_REQUEST_OPTION['TEST_CONFIG'] ),
			),
			site_url( '/' )
		);
	}

	/**
	 * Get the end user test config URL.
	 *
	 * @param string $idp_id The IDP ID.
	 * @return string The end user test config URL.
	 */
	public static function get_end_user_test_config_url( $idp_id ) {
		return add_query_arg(
			array(
				'option' => Plugin_Options::SAML_REQUEST_OPTION['END_USER_TEST_CONFIG'],
				'idp'    => $idp_id,
			),
			site_url( '/' )
		);
	}

	/**
	 * Checks if the current request is a test configuration request.
	 *
	 * @return bool True if it's a test configuration request, false otherwise.
	 */
	public static function is_test_configuration_request() {
		foreach ( array( 'option', 'RelayState' ) as $key ) {
			$option = ( 'RelayState' === $key ) ? self::sanitize_relay_state_request() : self::sanitize_request_data( $key );

			if ( 'testSSOLogin' === $option || 'testValidate' === $option || Plugin_Options::SAML_REQUEST_OPTION['TEST_CONFIG'] === $option ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Get the domain from the email.
	 *
	 * @param string $email The email.
	 * @return string|false The domain or false if the email is invalid.
	 */
	public static function get_domain_from_email( $email ) {
		$email = sanitize_email( $email );
		if ( empty( $email ) || ! is_email( $email ) ) {
			return false;
		}
		return substr( strrchr( $email, '@' ), 1 );
	}

	/**
	 * Checks if the user is logged in and handles the guest login case as well.
	 *
	 * @return bool True if the user is logged in, false otherwise.
	 */
	public static function mo_saml_is_user_logged_in() {
		if ( is_user_logged_in() ) {
			return true;
		}

		if ( ! empty( get_option( 'mo_enable_guest_login' ) ) && get_option( 'mo_enable_guest_login' ) ) {
			if ( ! empty( $_SESSION['mo_guest_login']['sessionIndex'] ) || ! empty( $_COOKIE['sessionIndex'] ) ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * This function checks whether the passed attribute is an array or not. Returns the zeroth element in the former case and the same attribute in latter.
	 *
	 * @param array $is_array_attribute The attribute to be checked.
	 * @return string The zeroth element if the attribute is an array
	 */
	public static function mo_saml_is_array( $is_array_attribute ) {
		return is_array( $is_array_attribute ) ? $is_array_attribute[0] : $is_array_attribute;
	}

	/**
	 * Coerce a SAML profile attribute value to a string for DTO fields.
	 *
	 * If the value is an array, index 0 is used. The result is a string unless invalid,
	 * in which case false is returned. When $preserve_null is true and the value is null,
	 * null is returned (e.g. display name “do not update”).
	 *
	 * @param mixed $value Raw attribute value.
	 * @param bool  $preserve_null When true, null is returned unchanged; otherwise null coerces to false.
	 * @return string|false|null
	 */
	public static function coerce_profile_attribute_string( $value, $preserve_null = false ) {
		if ( $preserve_null && null === $value ) {
			return null;
		}
		if ( is_array( $value ) ) {
			$value = array_key_exists( 0, $value ) ? $value[0] : null;
		}
		return is_string( $value ) ? $value : false;
	}

	/**
	 * WordPress blog ID stored for an environment in mosaml_subsites.
	 *
	 * When $environment_id is omitted, uses the selected environment (admin UI), via
	 * {@see DB_Utils::get_environment_details()} with $current_env false.
	 *
	 * @param int|string|null $environment_id Environment ID, or null to use the selected environment.
	 * @return int Blog ID; falls back to get_current_blog_id() if no subsites row exists.
	 */
	public static function get_subsite_id_for_environment( $environment_id = null ) {
		if ( null === $environment_id || '' === $environment_id ) {
			$environment_id = DB_Utils::get_environment_details( 'id', false );
		}

		if ( '' === $environment_id || null === $environment_id ) {
			return (int) get_current_blog_id();
		}
		$subsite = DB_Utils::get_records(
			Constants::DATABASE_TABLE_NAMES['subsites'],
			array( 'environment_id' => $environment_id, 'blog_id' => get_current_blog_id() ),
			true
		);
		if ( $subsite && isset( $subsite->id ) ) {
			return (int) $subsite->id;
		}
		return (int) get_current_blog_id();
	}

	/**
	 * Validate the given array.
	 *
	 * @param  array $validate_fields_array contains fields to be validated.
	 * @return boolean
	 */
	public static function mo_saml_check_empty_or_null( $validate_fields_array ) {
		foreach ( $validate_fields_array as $fields ) {
			if ( ! isset( $fields ) || empty( $fields ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Get the selected IDP ID from the URL or default.
	 *
	 * @param bool   $is_enterprise Whether enterprise version is enabled.
	 * @param array  $configured_idps Array of configured IDP IDs (excluding 'All IDPs').
	 * @param string $dropdown The dropdown name (unused in this logic).
	 * @return string The selected IDP ID.
	 */
	public static function get_selected_idp_id_from_url( $is_enterprise, $configured_idps = array(), $dropdown = '' ) {
		$selected_idp_param      = self::sanitize_get_data( 'idp' );
		$selected_environment_id = DB_Utils::get_environment_details( 'id', false );
		$default_idp_id          = self::get_default_idp( $selected_environment_id ) ? self::get_default_idp( $selected_environment_id )->idp_id : '';

		if ( in_array( $selected_idp_param, $configured_idps, true ) ) {
			if ( $is_enterprise ) {
				return $selected_idp_param;
			} else {
				return $default_idp_id;
			}
		} elseif ( $is_enterprise ) {
			if ( 'sso_link_idp' === $dropdown ) {
				return $default_idp_id;
			} else {
				$idp_id = ! empty( $default_idp_id ) ? $default_idp_id : 'All IDPs';
				return $idp_id;
			}
		} else {
			return $default_idp_id;
		}
	}

	/**
	 * Render the select your IDP dropdown.
	 *
	 * @param array  $configured_idps Array of configured IDPs.
	 * @param string $selected_idp_id The selected IDP ID.
	 */
	public static function add_select_your_idp_dropdown( $configured_idps, $selected_idp_id ) {
		$is_enterprise           = ( 'ENTERPRISE' === Constants::VERSION_HIERARCHY[ MOSAML_VERSION ] );
		$selected_environment_id = DB_Utils::get_environment_details( 'id', false );
		$default_idp             = self::get_default_idp( $selected_environment_id );

		?>
			<?php
			if ( ! empty( $is_enterprise ) ) :
				if ( null === $default_idp ) {
					$default_idp = (object) array(
						'idp_id'   => '',
						'idp_name' => '',
					);
				}
				?>
			<select name="mo_saml_attr_role_selected_idp" 
					id="mo_saml_attr_role_selected_idp" 
					class="mo-saml-idp-selector-width" 
					onchange="ChangeSelectedIDP(event)" 
					<?php echo esc_attr( self::disable_forms_if_no_idps_configured() ); ?>
					<?php echo esc_attr( Feature_Control::get_disabled_attribute( '4' ) ); ?>>

				<?php if ( ! empty( $configured_idps ) ) : ?>
					<?php foreach ( $configured_idps as $key => $idp ) : ?>
						<?php
						$idp_value    = esc_attr( $idp->idp_id );
						$idp_name     = esc_html( $idp->idp_name );
						$is_active    = ! empty( $idp->status ) && 'active' === $idp->status;
						$display_name = $idp_name;
						if ( $default_idp->idp_id === $idp->idp_id ) {
							$display_name .= ' (Default IDP)';
						}
						if ( ! $is_active && 'All IDPs' !== $idp->idp_name ) {
							$display_name .= ' (Inactive)';
						}
						?>

						<option value="<?php echo esc_attr( $idp_value ); ?>" 
								<?php selected( $selected_idp_id, $idp_value ); ?>>
							<?php echo esc_html( $display_name ); ?>
						</option>
					<?php endforeach; ?>
				<?php else : ?>
					<option value="" disabled>No IDPs configured</option>
				<?php endif; ?>
			</select>
				<?php
			else :
				if ( ! empty( $default_idp ) ) :
					?>
					<select name="mo_saml_attr_role_selected_idp" id="mo_saml_attr_role_selected_idp" class="mo-saml-idp-selector-width" disabled>
						<option value="<?php echo esc_attr( $default_idp->idp_id ); ?>" selected>
							<?php echo esc_html( $default_idp->idp_name ); ?>
						</option>
					</select>
				<?php else : ?>
					No Identity Provider configured or set as default
				<?php endif; ?>
			<?php endif; ?>
		<?php
	}

	/**
	 * Get configuration class instance for a specific module.
	 *
	 * @param string $class_name   Configuration class name.
	 * @param string $module_type  Module type (base, standard, premium, enterprise).
	 * @param array  $args         Optional constructor arguments.
	 * @return object|null Class instance or null if not found.
	 */
	public static function get_config_class_instance( $class_name, $module_type, $args = array() ) {
		$namespace       = self::get_config_module_namespace( $module_type );
		$full_class_name = $namespace . '\\' . $class_name;

		if ( class_exists( $full_class_name ) ) {
			$reflection = new ReflectionClass( $full_class_name );
			return $reflection->newInstanceArgs( $args );
		}

		return null;
	}

	/**
	 * Build module namespace dynamically from module type.
	 *
	 * @param string $module_type Module type (base, standard, premium, enterprise).
	 * @return string Module namespace.
	 */
	private static function get_config_module_namespace( $module_type ) {
		$module_type = ucfirst( strtolower( $module_type ) );
		return 'MOSAML\\Module\\' . $module_type . '\\Config';
	}

	/**
	 * Update test configuration attributes.
	 *
	 * @param array  $attributes The attributes to store.
	 * @param string $idp_id The IDP ID (primary key).
	 * @return void
	 */
	public static function update_test_config_attributes( $attributes, $idp_id ) {
		if ( ! is_array( $attributes ) || empty( $attributes ) ) {
			return;
		}

		DB_Utils::insert_or_update(
			Constants::DATABASE_TABLE_NAMES['idp_details'],
			array(
				'test_config_attributes' => $attributes,
			),
			array(
				'id'             => $idp_id,
				'environment_id' => DB_Utils::get_environment_details( 'id', false ),
			)
		);
	}

	/**
	 * Enable metadata sync and schedule cron job.
	 *
	 * @param object $data The metadata sync data.
	 * @return void
	 */
	public static function enable_metadata_sync( $data ) {
		$existing_event = wp_next_scheduled( Constants::METADATA_SYNC_CRON_HOOK, array( $data->idp_id ) );

		if ( $existing_event ) {
			wp_unschedule_event( $existing_event, Constants::METADATA_SYNC_CRON_HOOK, array( $data->idp_id ) );
		}

		wp_schedule_event( time(), $data->sync_time_interval, Constants::METADATA_SYNC_CRON_HOOK, array( $data->idp_id ) );
		wp_next_scheduled( Constants::METADATA_SYNC_CRON_HOOK, array( $data->idp_id ) );
	}

	/**
	 * Disable metadata sync and cleanup.
	 *
	 * @param object $data The metadata sync data.
	 * @return void
	 */
	public static function disable_metadata_sync( $data ) {
		wp_unschedule_event( wp_next_scheduled( Constants::METADATA_SYNC_CRON_HOOK, array( $data->idp_id ) ), Constants::METADATA_SYNC_CRON_HOOK, array( $data->idp_id ) );
	}

	/**
	 * Get user by username or email.
	 *
	 * @param string $username The username to search for.
	 * @param string $email The email to search for.
	 * @return \WP_User|false The WordPress user object or false if not found.
	 */
	public static function get_user_by_username_or_email( $username, $email ) {
		$user = get_user_by( 'login', $username );
		if ( ! $user ) {
			$user = get_user_by( 'email', $email );
		}
		return $user;
	}

	/**
	 * Checks if the user is an administrator.
	 *
	 * @param \WP_User $user The user object.
	 * @return bool True if the user is an administrator, false otherwise.
	 */
	public static function is_user_administrator( $user ) {
		return in_array( 'administrator', $user->roles, true );
	}

	/**
	 * Checks if the user is an manage option capability.
	 *
	 * @param \WP_User $user The user object.
	 * @return bool True if the user is an administrator, false otherwise.
	 */
	public static function mosaml_is_user_administrator( $user ) {
		return user_can( $user->ID, 'manage_options' );
	}

	/**
	 * Function to check if the SSL is used.
	 *
	 * @return boolean
	 */
	public static function mo_saml_is_ssl() {
		$forwarded_proto = '';
		if ( isset( $_SERVER['HTTP_X_FORWARDED_PROTO'] ) ) {
			$forwarded_proto = sanitize_text_field( wp_unslash( $_SERVER['HTTP_X_FORWARDED_PROTO'] ) );
		}

		if ( is_ssl() || 'https' === $forwarded_proto ) {
			return true;
		}
		return false;
	}

	/**
	 * Get the IDP ID from the session.
	 * Checks both SAML and guest login sessions.
	 *
	 * @return string The IDP ID from session, or empty string if not found.
	 */
	public static function get_idp_id_from_session() {
		if ( ! empty( $_SESSION['mo_saml']['logged_in_with_idp'] ) ) {
			return sanitize_text_field( $_SESSION['mo_saml']['logged_in_with_idp'] );
		}

		if ( isset( $_SESSION['mo_guest_login']['logged_in_with_idp'] ) ) {
			return sanitize_text_field( $_SESSION['mo_guest_login']['logged_in_with_idp'] );
		}

		return '';
	}

	/**
	 * Convert IDP details object to array format for mo_guest_login action
	 *
	 * @param object $idp_details The IDP details object.
	 * @return array The IDP details as array.
	 */
	public static function convert_idp_details_to_array( $idp_details ) {
		if ( ! is_object( $idp_details ) ) {
			return array();
		}

		// Map object properties to array keys matching the expected format.
		$idp_array = array(
			'idp_name'                 => isset( $idp_details->idp_id ) ? $idp_details->idp_id : '',
			'idp_display_name'         => isset( $idp_details->idp_name ) ? $idp_details->idp_name : '',
			'sso_binding_type'         => isset( $idp_details->sso_binding ) ? $idp_details->sso_binding : '',
			'sso_url'                  => isset( $idp_details->sso_url ) ? $idp_details->sso_url : '',
			'slo_binding_type'         => isset( $idp_details->slo_binding ) ? $idp_details->slo_binding : '',
			'slo_url'                  => isset( $idp_details->slo_url ) ? $idp_details->slo_url : '',
			'slo_response_url'         => isset( $idp_details->slo_response_url ) ? $idp_details->slo_response_url : '',
			'idp_entity_id'            => isset( $idp_details->entity_id ) ? $idp_details->entity_id : '',
			'nameid_format'            => isset( $idp_details->name_id_format ) ? $idp_details->name_id_format : '',
			'x509_certificate'         => isset( $idp_details->idp_certificate ) ? $idp_details->idp_certificate : array(),
			'response_signed'          => 'checked',
			'assertion_signed'         => 'checked',
			'request_signed'           => isset( $idp_details->sign_sso_slo_request ) && $idp_details->sign_sso_slo_request ? 'checked' : 'unchecked',
			'mo_saml_encoding_enabled' => isset( $idp_details->character_encoding ) ? $idp_details->character_encoding : 'checked',
			'enable_idp'               => isset( $idp_details->status ) && 'active' === $idp_details->status ? 1 : 0,
			'custom_login_text'        => '',
			'custom_greeting_text'     => '',
			'greeting_name'            => '',
			'custom_logout_text'       => '',
			'saml_request'             => '',
			'saml_response'            => '',
			'sp_certificate'           => isset( $idp_details->sp_certificate ) ? $idp_details->sp_certificate : '',
			'sp_private_key'           => isset( $idp_details->sp_private_key ) ? $idp_details->sp_private_key : '',
			'test_status'              => '',
		);

		return $idp_array;
	}

	/**
	 * Get the default IDP for the current environment.
	 *
	 * @param int $environment_id The environment ID.
	 * @return object|null The default IDP object or null if not found.
	 */
	public static function get_default_idp( $environment_id = '' ) {
		if ( empty( $environment_id ) ) {
			$environment_id = DB_Utils::get_environment_details( 'id' );
		}

		$active_idps = self::mo_saml_get_active_idps( $environment_id );

		if ( empty( $active_idps ) ) {
			return null;
		}

		$valid_idps = array_filter(
			$active_idps,
			function ( $idp ) {
				return strtolower( trim( $idp->idp_name ) ) !== 'all idps';
			}
		);

		if ( empty( $valid_idps ) ) {
			return null;
		}

		$valid_idps = array_values( $valid_idps );

		$default_idp = null;
		foreach ( $valid_idps as $idp ) {
			if ( ! empty( $idp->default_idp ) && 1 === (int) $idp->default_idp ) {
				$default_idp = $idp;
				break;
			}
		}

		if ( null === $default_idp ) {
			$default_idp = $valid_idps[0];
		}

		return $default_idp;
	}

	/**
	 * Deactivate non-default IDPs when the plugin version is premium or lower.
	 *
	 * Enterprise version supports multiple active IDPs. For all other versions,
	 * only the default IDP should remain active. This method sets the status of
	 * all non-default IDPs (excluding "All IDPs") to 'inactive'.
	 *
	 * @param int    $selected_environment_id The environment ID.
	 * @param string $default_idp_id          The default IDP ID.
	 *
	 * @return void
	 */
	public static function deactivate_non_default_idps( $selected_environment_id, $default_idp_id ) {
			$idp_details = DB_Utils::get_records(
				Constants::DATABASE_TABLE_NAMES['idp_details'],
				array( 'environment_id' => $selected_environment_id )
			);

			if ( empty( $idp_details ) || ! is_array( $idp_details ) ) {
				return;
			}

		$environment_idps         = array();
		$active_environment_idps = array();

		foreach ( $idp_details as $idp ) {
			if ( 'All IDPs' === $idp->idp_name ) {
				continue;
			}
			$environment_idps[] = $idp;
			if ( 'active' === $idp->status ) {
				$active_environment_idps[] = $idp;
			}
		}

		$id_sort = static function ( $lhs_idp, $rhs_idp ) {
			return $lhs_idp->id <=> $rhs_idp->id;
		};
		usort( $environment_idps, $id_sort );
		usort( $active_environment_idps, $id_sort );

		$encrypted_sp_limit     = get_option( 'no_of_sp', '' );
		$license_sp_limit_value = class_exists( Mo_License_Service_Utility::class )
			? Mo_License_Service_Utility::mo_decrypt_data( $encrypted_sp_limit )
			: $encrypted_sp_limit;

		$max_active_idps = ( 4 !== MOSAML_VERSION )
			? 1
			: ( is_numeric( $license_sp_limit_value ) ? max( 1, (int) $license_sp_limit_value ) : 1 );

		if ( count( $active_environment_idps ) <= $max_active_idps ) {
				return;
			}

		$ids_to_keep_active = array();

			if ( ! empty( $default_idp_id ) ) {
			foreach ( $active_environment_idps as $idp ) {
					if ( $idp->idp_id === $default_idp_id ) {
					$ids_to_keep_active[] = $default_idp_id;
						break;
					}
				}
			}

		foreach ( $active_environment_idps as $idp ) {
			if ( count( $ids_to_keep_active ) >= $max_active_idps ) {
					break;
				}
				if ( $idp->idp_id === $default_idp_id ) {
					continue;
				}
			$ids_to_keep_active[] = $idp->idp_id;
			}

		$current_active_ids = array_map(
				static function ( $idp ) {
					return $idp->idp_id;
				},
			$active_environment_idps
			);
		$ids_to_deactivate = array_diff( $current_active_ids, $ids_to_keep_active );

		foreach ( $ids_to_deactivate as $idp_id ) {
				DB_Utils::insert_or_update(
					Constants::DATABASE_TABLE_NAMES['idp_details'],
					array( 'status' => 'inactive' ),
					array(
						'idp_id'         => $idp_id,
						'environment_id' => $selected_environment_id,
					)
				);
			}
	}

	/**
	 * Ensures a valid default IDP exists and deactivates non-default IDPs for non-enterprise versions.
	 *
	 * @return void
	 */
	public static function enforce_default_idp_state() {
		$selected_environment_id = DB_Utils::get_environment_details( 'id', false );
		$default_idp             = self::get_default_idp( $selected_environment_id );
		$default_idp_id          = $default_idp ? $default_idp->idp_id : '';
		self::make_default_idp_if_not_exists( $selected_environment_id, $default_idp_id );
		self::deactivate_non_default_idps( $selected_environment_id, $default_idp_id );
	}

	/**
	 * Make the default IDP if it does not exist.
	 *
	 * @param int    $selected_environment_id The environment ID.
	 * @param string $default_idp_id          The default IDP ID.
	 *
	 * @return void
	 */
	public static function make_default_idp_if_not_exists( $selected_environment_id, $default_idp_id ) {
		if ( ! empty( $default_idp_id ) ) {
			DB_Utils::insert_or_update(
				Constants::DATABASE_TABLE_NAMES['idp_details'],
				array( 'default_idp' => false ),
				array(
					'environment_id' => $selected_environment_id,
				)
			);

			DB_Utils::insert_or_update(
				Constants::DATABASE_TABLE_NAMES['idp_details'],
				array( 'default_idp' => true ),
				array(
					'idp_id'         => $default_idp_id,
					'environment_id' => $selected_environment_id,
				)
			);
		}
	}

	/**
	 * Get the idp_details from the shortcode configuration.
	 *
	 * @param string $idp_id IDP ID.
	 * @param int    $environment_id Environment ID.
	 *
	 * @return object IDP data.
	 */
	public static function get_idp_details_from_idp_id( $idp_id, $environment_id ) {
		if ( self::is_legacy_data_fallback_required() ) {
			$where = array(
				'idp_id'         => $idp_id,
				'environment_id' => $environment_id,
			);
			return apply_filters( 'mosaml_legacy_data_fallback_object', self::get_handler_object( 'sp_setup_data', true, 'admin' ), $where );
		}

		$idp_details = null;
		$idp_details = DB_Utils::get_records(
			Constants::DATABASE_TABLE_NAMES['idp_details'],
			array(
				'idp_id'         => $idp_id,
				'environment_id' => $environment_id,
			),
			true
		);

		if ( empty( $idp_details->idp_name ) ) {
			$idp_details = DB_Utils::get_records(
				Constants::DATABASE_TABLE_NAMES['idp_details'],
				array(
					'idp_name'       => $idp_id,
					'environment_id' => $environment_id,
				),
				true
			);
		}

		return $idp_details;
	}

	/**
	 * Get active IDPs for the current environment.
	 *
	 * @param int $environment_id The environment ID.
	 * @return array The active IDPs.
	 */
	public static function mo_saml_get_active_idps( $environment_id = '' ) {
		if ( empty( $environment_id ) ) {
			$environment_id = DB_Utils::get_environment_details( 'id' );
		}

		$idps = DB_Utils::get_records(
			Constants::DATABASE_TABLE_NAMES['idp_details'],
			array(
				'environment_id' => $environment_id,
				'status'         => 'active',
			)
		);

		return $idps;
	}

	/**
	 * Whether the number of configured IDPs (excluding "All IDPs") exceeds the licensed limit.
	 *
	 * @param int|string $environment_id Environment ID, or empty to use the current environment.
	 * @return bool True if the limit is exceeded, false otherwise.
	 */
	public static function mo_saml_is_idp_license_limit_exceeded( $environment_id = '' ) {
		if ( empty( $environment_id ) ) {
			$environment_id = DB_Utils::get_environment_details( 'id', false );
		}

		$encrypted_sp_limit = get_option( 'no_of_sp', '' );
		$sp_limit_value     = class_exists( Mo_License_Service_Utility::class )
			? Mo_License_Service_Utility::mo_decrypt_data( $encrypted_sp_limit )
			: $encrypted_sp_limit;

		$sp_limit = is_numeric( $sp_limit_value ) ? max( 1, (int) $sp_limit_value ) : 1;

		$environment_idp_records = DB_Utils::get_records(
			Constants::DATABASE_TABLE_NAMES['idp_details'],
			array( 'environment_id' => $environment_id )
		);

		if ( ! is_array( $environment_idp_records ) ) {
			return false;
		}

		$configured_real_idps = array_filter(
			$environment_idp_records,
			static function ( $idp ) {
				return 'All IDPs' !== $idp->idp_name;
			}
		);

		return count( $configured_real_idps ) > $sp_limit;
	}

	/**
	 * Check if no IDPs are configured for the current environment.
	 *
	 * @param int $environment_id The environment ID.
	 * @return bool True if no IDPs are configured, false otherwise.
	 */
	public static function mo_saml_is_no_idps_configured( $environment_id = '' ) {
		if ( empty( $environment_id ) ) {
			$environment_id = DB_Utils::get_environment_details( 'id' );
		}

		return empty( self::mo_saml_get_active_idps( $environment_id ) );
	}

	/**
	 * Check if forms should be disabled and return the disabled attribute.
	 *
	 * Forms are disabled when either there are no active IDPs configured
	 * or the license-specific feature is not enabled for this installation.
	 *
	 * @return string Returns 'disabled' if forms should be disabled, empty string otherwise.
	 */
	public static function disable_forms_if_no_idps_configured() {
		$selected_environment_id = DB_Utils::get_environment_details( 'id', false );
		$disable_forms           = self::mo_saml_is_no_idps_configured( $selected_environment_id ) || ! Feature_Control::free_or_license_specific_feature_enabled();
		return $disable_forms ? 'disabled' : '';
	}

	/**
	 * Check if forms should be disabled and return the disabled attribute.
	 *
	 * Forms are disabled when either there are no active IDPs configured
	 * or the license-specific feature is not enabled for this installation.
	 *
	 * @return string Returns 'disabled' if forms should be disabled, empty string otherwise.
	 */
	public static function disable_forms_if_no_idps_configured_bool() {
		$selected_environment_id = DB_Utils::get_environment_details( 'id', false );
		$disable_forms           = self::mo_saml_is_no_idps_configured( $selected_environment_id ) || ! Feature_Control::free_or_license_specific_feature_enabled();
		return $disable_forms;
	}

	/**
	 * Echo 'disabled' attribute based on the condition.
	 *
	 * @param bool $condition The condition to check.
	 */
	public static function mo_saml_get_disabled_attribute( $condition ) {
		return $condition ? 'disabled' : '';
	}

	/**
	 * Get the active tab.
	 *
	 * @return string The active tab.
	 */
	public static function get_active_tab() {
		$selected_environment_id = DB_Utils::get_environment_details( 'id', false );
		$no_idp_configured       = self::mo_saml_is_no_idps_configured( $selected_environment_id );
		if ( 1 === MOSAML_VERSION ) {
			if ( ! $no_idp_configured ) {
				$active_tab = 'sso_redirection_settings';
			} else {
				$active_tab = 'sp_setup';
			}
		} elseif ( ! self::handle_license_calls( 'is_license_verified', 'library', false ) || ! self::handle_license_calls( 'is_license_valid', 'library', false ) ) {
			$active_tab = 'account_settings';
		} elseif ( ! $no_idp_configured ) {
			$active_tab = 'sso_redirection_settings';
		} else {
			$active_tab = 'sp_setup';
		}
		return $active_tab;
	}

	/**
	 * Get the "All IDPs" IDP details for the current environment.
	 *
	 * @param int $environment_id The environment ID.
	 * @return object|null The "All IDPs" IDP details or null if not found.
	 */
	public static function get_all_idps_idp( $environment_id = '' ) {
		if ( empty( $environment_id ) ) {
			$environment_id = DB_Utils::get_environment_details( 'id', false );
		}

		$all_idps_idp = DB_Utils::get_records(
			'mosaml_idp_details',
			array(
				'environment_id' => $environment_id,
				'idp_name'       => 'All IDPs',
			),
			true
		);
		return $all_idps_idp;
	}


	/**
	 * Ensure color string has hash prefix.
	 *
	 * @param string $color The color string to check and modify.
	 * @return string The color string with a hash prefix.
	 */
	public static function mo_saml_color_hash_prefix( $color ) {
		return strpos( $color, '#' ) === 0 ? $color : '#' . $color;
	}

	/**
	 * Check if legacy data fallback is required.
	 *
	 * @return bool True if legacy data fallback is required, false otherwise.
	 */
	public static function is_legacy_data_fallback_required() {
		if ( ! DB_Utils::all_tables_exist() || 'completed' !== get_option( Constants::DATABASE_UPDATE_STATUS ) ) {
			return true;
		}

		if ( 'in_progress' === get_option( Constants::MIGRATION_STATUS, '' ) ) {
			return true;
		}

		return false;
	}

	/**
	 * Render the plugin header with logo, version, and action buttons.
	 *
	 * @return void
	 */
	public static function render_plugin_header() {
		?>
		<div class="mosaml-heading-div-flex-row mosaml-width-100">
			<img src="<?php echo esc_url( plugins_url( '', MOSAML_PLUGIN_FILE ) ); ?>/static/css/images/mo-icon.webp" class="mosaml-header-logo" alt="miniOrange logo" >
			<span class="mosaml-plugin-header-name">miniOrange SAML SSO</span>
			<span class="mosaml-plugin-header-version">
				[ v<?php echo esc_html( Constants::VERSION_NUMBER[ MOSAML_VERSION ] ); ?> ]
			</span>
			<div style="display:flex;gap:0.5rem;">
				<a class="mosaml-header-btn mosaml-orange-button" href="<?php echo esc_url( Constants::PRICING_PAGE_URL ); ?>" target="_blank">
					<b>Licensing Plans</b>
				</a>
				<a class="mosaml-header-btn mosaml-blue-btn" href="<?php echo esc_url( Constants::DOCUMENTATION_URL ); ?>" target="_blank">
					<b>Plugin Documentation</b>
				</a>
				<a class="mosaml-header-btn mosaml-blue-btn" href="<?php echo esc_url( Constants::FAQ_URL ); ?>" target="_blank">
					<b>FAQs</b>
				</a>
			</div>
		</div>
		<?php
	}

	/**
	 * Check if a URL is a third-party URL (not belonging to the current site).
	 *
	 * @param string $url The URL to check.
	 * @return bool True if the URL is a third-party URL, false otherwise.
	 */
	public static function is_3rd_party_url( $url ) {
		if ( empty( $url ) || ! is_string( $url ) ) {
			return false;
		}

		$url = esc_url_raw( trim( $url ) );
		if ( empty( $url ) || ! filter_var( $url, FILTER_VALIDATE_URL ) ) {
			return false;
		}

		$parsed_url = wp_parse_url( $url );
		if ( empty( $parsed_url['host'] ) || empty( $parsed_url['scheme'] ) ) {
			return false;
		}

		if ( ! isset( $parsed_url['host'] ) ) {
			return false;
		}

		$site_url    = get_site_url();
		$parsed_site = wp_parse_url( $site_url );

		return isset( $parsed_site['host'] ) && ( $parsed_site['host'] !== $parsed_url['host'] );
	}

	/**
	 * Check if a plugin is active.
	 *
	 * @param string $plugin_slug The plugin slug.
	 * @return bool True if the plugin is active, false otherwise.
	 */
	public static function is_plugin_active( $plugin_slug ) {
		$active_plugins = get_option( 'active_plugins' );
		return in_array( $plugin_slug, (array) $active_plugins, true );
	}

	/**
	 * Checks if any configured IDP's login URL (SSO URL) or SP Entity ID (ACS-related URL) contains the given keyword.
	 *
	 * @param string   $keyword              The keyword to search for (case-insensitive).
	 * @param int|null $environment_id       Optional. Environment ID to check. Defaults to current environment. Ignored when $check_all_environments is true.
	 * @param bool     $check_all_environments Optional. When true, checks IDPs across all environments. Default false.
	 * @return bool True if any IDP's login URL or SP Entity ID contains the keyword, false otherwise.
	 */
	public static function any_idp_url_contains_keyword( $keyword, $environment_id = null, $check_all_environments = false ) {
		if ( empty( $keyword ) || ! is_string( $keyword ) ) {
			return false;
		}

		if ( $check_all_environments ) {
			$all_environments = DB_Utils::get_records( Constants::DATABASE_TABLE_NAMES['environments'], array() );

			if ( ! empty( $all_environments ) ) {
				if ( ! is_array( $all_environments ) ) {
					$all_environments = array( $all_environments );
				}

				foreach ( $all_environments as $env ) {
					if ( ! is_object( $env ) || empty( $env->id ) ) {
						continue;
					}
					if ( self::any_idp_url_contains_keyword( $keyword, $env->id ) ) {
						return true;
					}
				}

				return false;
			}
		}

		$keyword_lower = strtolower( $keyword );

		if ( null === $environment_id ) {
			$environment_id = DB_Utils::get_environment_details( 'id', true );
		}

		$tab_handler = self::get_handler_object( 'sp_setup_data', true, 'admin' );
		if ( ! $tab_handler ) {
			return false;
		}

		$idp_details = $tab_handler->get_data(
			array( 'environment_id' => $environment_id ),
			false
		);

		if ( empty( $idp_details ) || ! is_array( $idp_details ) ) {
			return false;
		}

		foreach ( $idp_details as $idp ) {
			if ( ! is_object( $idp ) || ( isset( $idp->idp_name ) && 'All IDPs' === $idp->idp_name ) ) {
				continue;
			}

			$login_url = isset( $idp->sso_url ) ? (string) $idp->sso_url : '';
			if ( ! empty( $login_url ) && false !== strpos( strtolower( $login_url ), $keyword_lower ) ) {
				return true;
			}

			$sp_entity_id = isset( $idp->sp_entity_id ) ? (string) $idp->sp_entity_id : '';
			if ( ! empty( $sp_entity_id ) && false !== strpos( strtolower( $sp_entity_id ), $keyword_lower ) ) {
				return true;
			}
		}

		return false;
	}
}
