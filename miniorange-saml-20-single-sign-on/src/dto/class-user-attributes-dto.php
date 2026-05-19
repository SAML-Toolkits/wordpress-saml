<?php
/**
 * User attributes DTO.
 *
 * @package miniorange-saml-20-single-sign-on
 */

namespace MOSAML\SRC\DTO;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\SRC\Utils\Utility;

/**
 * User Attributes DTO.
 *
 * @package MOSAML\SRC\DTO
 */
class User_Attributes_DTO {

	/**
	 * User name.
	 *
	 * @var string
	 */
	private $user_name;

	/**
	 * Email.
	 *
	 * @var string
	 */
	private $email;

	/**
	 * First name.
	 *
	 * @var string
	 */
	private $first_name;

	/**
	 * Last name.
	 *
	 * @var string
	 */
	private $last_name;

	/**
	 * Nick name.
	 *
	 * @var string
	 */
	private $nick_name;

	/**
	 * Display name.
	 *
	 * @var string|null
	 */
	private $display_name;

	/**
	 * Attribute Array.
	 *
	 * @var array
	 */
	private $custom_attributes = array();

	/**
	 * Get user name.
	 *
	 * @return string
	 */
	public function get_username() {
		return $this->user_name;
	}

	/**
	 * Get email.
	 *
	 * @return string
	 */
	public function get_email() {
		return $this->email;
	}

	/**
	 * Get first name.
	 *
	 * @return string
	 */
	public function get_first_name() {
		return $this->first_name;
	}

	/**
	 * Get last name.
	 *
	 * @return string
	 */
	public function get_last_name() {
		return $this->last_name;
	}

	/**
	 * Get nick name.
	 *
	 * @return string
	 */
	public function get_nick_name() {
		return $this->nick_name;
	}

	/**
	 * Get display name.
	 *
	 * @return string|null
	 */
	public function get_display_name() {
		return $this->display_name;
	}

	/**
	 * Get Custom Attributes.
	 *
	 * @return array
	 */
	public function get_custom_attributes() {
		return $this->custom_attributes;
	}

	/**
	 * Set user name.
	 *
	 * SAML may send an array of values; the first element is used. Non-string values become empty;
	 * missing username/email is reported in the login handler (e.g. WPSAMLERR037).
	 *
	 * @param mixed $user_name User name.
	 */
	public function set_username( $user_name ) {
		$coerced         = Utility::coerce_profile_attribute_string( $user_name );
		$this->user_name = ( false === $coerced ) ? '' : $coerced;
	}

	/**
	 * Set email.
	 *
	 * @param mixed $email Email.
	 */
	public function set_email( $email ) {
		$coerced         = Utility::coerce_profile_attribute_string( $email );
		$this->email     = ( false === $coerced ) ? '' : $coerced;
	}

	/**
	 * Set first name.
	 *
	 * @param mixed $first_name First name.
	 */
	public function set_first_name( $first_name ) {
		$coerced           = Utility::coerce_profile_attribute_string( $first_name );
		$this->first_name  = ( false === $coerced ) ? '' : $coerced;
	}

	/**
	 * Set last name.
	 *
	 * @param mixed $last_name Last name.
	 */
	public function set_last_name( $last_name ) {
		$coerced          = Utility::coerce_profile_attribute_string( $last_name );
		$this->last_name  = ( false === $coerced ) ? '' : $coerced;
	}

	/**
	 * Set nick name.
	 *
	 * @param mixed $nick_name Nick name.
	 */
	public function set_nick_name( $nick_name ) {
		$coerced          = Utility::coerce_profile_attribute_string( $nick_name );
		$this->nick_name  = ( false === $coerced ) ? '' : $coerced;
	}

	/**
	 * Set display name.
	 *
	 * Pass null to skip updating display name (e.g. premium “do not update display name”).
	 *
	 * @param mixed $display_name Display name.
	 */
	public function set_display_name( $display_name ) {
		$coerced            = Utility::coerce_profile_attribute_string( $display_name, true );
		$this->display_name = ( null === $coerced ) ? null : ( ( false === $coerced ) ? '' : $coerced );
	}

	/**
	 * Set Custom Attributes.
	 *
	 * @param array $custom_attributes Custom Attributes.
	 */
	public function set_custom_attributes( $custom_attributes ) {
		$this->custom_attributes = $custom_attributes;
	}
}
