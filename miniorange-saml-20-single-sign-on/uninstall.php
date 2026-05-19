<?php
/**
 * Uninstall the plugin.
 *
 * @package miniorange-saml-20-single-sign-on
 */

use MOSAML\SRC\Handler\Database_Cleanup_Handler;

if ( ! defined( 'ABSPATH' ) || ! defined( 'WP_UNINSTALL_PLUGIN' ) ) {
	exit;
}

if ( ! defined( 'MOSAML_PLUGIN_DIR' ) ) {
	define( 'MOSAML_PLUGIN_DIR', plugin_dir_path( __FILE__ ) );
}

$mosaml_autoloader = 'autoloader.php';
require_once __DIR__ . DIRECTORY_SEPARATOR . $mosaml_autoloader;
spl_autoload_register( 'mosaml_autoload_files' );

Database_Cleanup_Handler::delete_plugin_license_detail();
Database_Cleanup_Handler::drop_plugin_tables_and_options_on_uninstall();
