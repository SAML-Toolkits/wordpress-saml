<?php
/**
 * Autoloader for the plugin.
 *
 * @package miniorange-saml-20-single-sign-on
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Function to autoload the files of the WordPress SAML SSO Plugin.
 *
 * @param string $class_name Name of the class to load.
 * @return void
 */
function mosaml_autoload_files( $class_name ) {
	$namespace           = 'MOSAML';
	$namespace_separator = '\\';

	if ( null !== $namespace && strpos( $class_name, $namespace . $namespace_separator ) !== 0 ) {
		return;
	}

	$relative_class   = substr( $class_name, strlen( $namespace . $namespace_separator ) );
	$relative_path    = strtolower( str_replace( array( '\\', '_' ), array( DIRECTORY_SEPARATOR, '-' ), $relative_class ) );
	$final_class_name = 'class-' . basename( $relative_path ) . '.php';
	$file_path        = MOSAML_PLUGIN_DIR . str_replace( basename( $relative_path ), $final_class_name, $relative_path );

	if ( file_exists( $file_path ) ) {
		require $file_path;
	}
}
