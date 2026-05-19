<?php
/**
 * This file is part of miniOrange WP plugin.
 *
 * @package    miniOrange
 * @author     miniOrange Security Software Pvt. Ltd.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

spl_autoload_register(
	static function ( $class_name ) {
		$namespace = 'MOSAML\LicenseLibrary';

		if ( strpos( $class_name, $namespace ) !== 0 ) {
			return;
		}

		$base_dir = __DIR__ . DIRECTORY_SEPARATOR . 'src';

		// Remove namespace, replace namespace separators with directory separators, and convert to lowercase.
		$relative_class = strtolower( str_replace( '\\', DIRECTORY_SEPARATOR, substr( $class_name, strlen( $namespace ) ) ) );

		// Get the namespace class i.e. last part of string after separator.
		$namespace_class = strrchr( $relative_class, DIRECTORY_SEPARATOR );

		// Replace underscores with dashes and prepend class to create file name from namespace class.
		$final_class_name = 'class-' . str_replace( '_', '-', str_replace( DIRECTORY_SEPARATOR, '', $namespace_class ) ) . '.php';

		// Replace.
		$relative_file_path = str_replace( $namespace_class, DIRECTORY_SEPARATOR . $final_class_name, $relative_class );

		// Concatenate the file path.
		$file_path = $base_dir . $relative_file_path;

		if ( file_exists( $file_path ) ) {
			require_once $file_path;
		}
	}
);
