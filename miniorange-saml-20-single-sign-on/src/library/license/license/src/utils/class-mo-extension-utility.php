<?php
/**
 * This file is part of miniOrange WP plugin.
 *
 * @package    miniOrange
 * @author     miniOrange Security Software Pvt. Ltd.
 */

namespace MOSAML\LicenseLibrary\Utils;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\LicenseLibrary\Exceptions\CURL_Extension_Disabled_Exception;
use MOSAML\LicenseLibrary\Exceptions\DOM_Extension_Disabled_Exception;
use MOSAML\LicenseLibrary\Exceptions\OpenSSL_Extension_Disabled_Exception;

/**
 * Utility for checking required PHP extensions.
 * Can be used by the license library, update framework, or any other component.
 */
class Mo_Extension_Utility {

	/**
	 * PHP extensions required for remote requests, API calls, etc.
	 *
	 * @var array<string>
	 */
	const REQUIRED_EXTENSIONS = array( 'dom', 'curl', 'openssl' );

	/**
	 * Validate that required PHP extensions are loaded.
	 *
	 * @return bool True if all required extensions are available, false otherwise.
	 */
	public static function validate_required_extensions() {
		try {
			self::check_required_extensions();
			return true;
		} catch ( DOM_Extension_Disabled_Exception $ex ) {
			return false;
		} catch ( CURL_Extension_Disabled_Exception $ex ) {
			return false;
		} catch ( OpenSSL_Extension_Disabled_Exception $ex ) {
			return false;
		}
	}

	/**
	 * Check that required PHP extensions are installed. Throws if any are missing.
	 *
	 * @throws DOM_Extension_Disabled_Exception If the DOM extension is not installed.
	 * @throws CURL_Extension_Disabled_Exception If the cURL extension is not installed.
	 * @throws OpenSSL_Extension_Disabled_Exception If the OpenSSL extension is not installed.
	 */
	public static function check_required_extensions() {
		$missing = array();
		foreach ( self::REQUIRED_EXTENSIONS as $ext ) {
			if ( ! extension_loaded( $ext ) ) {
				$missing[] = $ext;
			}
		}
		foreach ( $missing as $ext ) {
			self::throw_extension_exception( $ext );
		}
	}

	/**
	 * Throw the appropriate exception for a missing PHP extension.
	 *
	 * @param string $ext Extension name (e.g. 'dom', 'curl', 'openssl').
	 * @throws DOM_Extension_Disabled_Exception If the DOM extension is not installed.
	 * @throws CURL_Extension_Disabled_Exception If the cURL extension is not installed.
	 * @throws OpenSSL_Extension_Disabled_Exception If the OpenSSL extension is not installed.
	 */
	private static function throw_extension_exception( $ext ) {
		switch ( $ext ) {
			case 'dom':
				throw new DOM_Extension_Disabled_Exception( 'DOM extension is not installed.' );
			case 'curl':
				throw new CURL_Extension_Disabled_Exception( 'cURL extension is not installed.' );
			case 'openssl':
				throw new OpenSSL_Extension_Disabled_Exception( 'OpenSSL extension is not installed.' );
		}
	}
}
