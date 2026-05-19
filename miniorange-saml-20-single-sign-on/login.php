<?php
/**
 * Plugin Name: miniOrange SAML SSO
 * Plugin URI: https://miniorange.com/
 * Description: miniOrange SAML SSO plugin enables user to perform Single Sign On with any SAML 2.0 enabled Identity Provider on the WordPress site.
 * Version: 26.0.0
 * Author: miniOrange
 * Author URI: https://miniorange.com/
 * License: Expat
 * License URI: https://plugins.miniorange.com/mit-license
 *
 * @package miniorange-saml-20-single-sign-on
 */

namespace MOSAML;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\SRC\Hook\Register_Hooks;
use MOSAML\SRC\Utils\Utility;
use MOSAML\SRC\Constant\Plugin_Files_Constants;

$mosaml_autoloader = 'autoloader.php';
require_once $mosaml_autoloader;

spl_autoload_register( 'mosaml_autoload_files' );

define( 'MOSAML_PLUGIN_DIR', plugin_dir_path( __FILE__ ) );
define( 'MOSAML_PLUGIN_FILE', __FILE__ );
define( 'MOSAML_VERSION', Utility::get_current_version() );

require_once Plugin_Files_Constants::INTEGRATION_FUNCTIONS;
require_once Plugin_Files_Constants::LIBRARY_ROBRICHARDS_AUTOLOADER;
if ( file_exists( Plugin_Files_Constants::LIBRARY_LICENSE_AUTOLOADER ) ) {
	require_once Plugin_Files_Constants::LIBRARY_LICENSE_AUTOLOADER;
}

/**
 * Main file of the WordPress SAML SSO Plugin.
 */
class SAML_MO_Login {

	/**
	 * Construct function of the SAML_MO_Login class.
	 */
	public function __construct() {
		Utility::initialize_license_library();
		Register_Hooks::register_hooks();
	}
}

new SAML_MO_Login();
