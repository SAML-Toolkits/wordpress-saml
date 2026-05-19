<?php
/**
 * To use global instance variable for all classes.
 *
 * @package miniorange-saml-20-single-sign-on
 */

namespace MOSAML\Traits;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

trait Instance {

	/** Global object declaration
	 *
	 * @var instance To use global instance variable for all classes.
	 **/
	private static $instance = null;

	/**
	 * Function to return the class object.
	 *
	 * @return Object
	 */
	public static function instance() {
		if ( is_null( self::$instance ) ) {
			self::$instance = new self();
		}
		return self::$instance;
	}
}
