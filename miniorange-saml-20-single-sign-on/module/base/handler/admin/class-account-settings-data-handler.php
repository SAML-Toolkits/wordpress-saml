<?php
/**
 * Account Settings Data Handler.
 *
 * @package miniorange-saml-20-single-sign-on
 */

namespace MOSAML\Module\Base\Handler\Admin;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\SRC\Interfaces\Form_Data_Handler_Interface;
use MOSAML\SRC\Utils\Utility;
use MOSAML\SRC\Utils\Error_Success_Message;
use MOSAML\SRC\Classes\Mo_Customer;

/**
 * Account Settings Data Handler.
 */
class Account_Settings_Data_Handler implements Form_Data_Handler_Interface {

	/**
	 * Register email.
	 *
	 * @var string
	 */
	public $register_email;

	/**
	 * Password.
	 *
	 * @var string
	 */
	public $password;

	/**
	 * Confirm password.
	 *
	 * @var string
	 */
	public $confirm_password;

	/**
	 * Validate and save the data.
	 *
	 * @return void
	 */
	public function validate_and_save_data() {
		// ToDo: Check if it is the LoginEmail or RegisterEmail.

		$this->register_email   = Utility::sanitize_post_data( 'registerEmail' );
		$this->password         = Utility::sanitize_post_data( 'password' );
		$this->confirm_password = Utility::sanitize_post_data( 'confirmPassword' );

		if ( Utility::mo_saml_check_empty_or_null( array( $this->confirm_password ) ) ) {
			Error_Success_Message::show_admin_notice( 'All the fields are required. Please enter valid entries.' );
			return;
		} elseif ( strcmp( $this->password, $this->confirm_password ) !== 0 ) {
			Error_Success_Message::show_admin_notice( 'Password and Confirm Password do not match. Please enter valid entries.' );
			return;
		} elseif ( ! filter_var( $this->register_email, FILTER_VALIDATE_EMAIL ) ) {
			Error_Success_Message::show_admin_notice( 'Invalid Email. Please enter a valid email.' );
			return;
		}

		$customer = new Mo_Customer();

		$content = json_decode( $customer->check_customer( $this->register_email ), true );
		if ( ! is_null( $content ) ) {
			if ( strcasecmp( $content['status'], 'CUSTOMER_NOT_FOUND' ) === 0 ) {
				$response = self::mo_saml_create_customer( $customer, $this->register_email, $this->password );
			} else {
				$response = self::mo_saml_get_current_customer( $customer );
			}
		}
	}

	/**
	 * Get the data.
	 *
	 * @param array $where The where clause to filter the data.
	 * @return object The data.
	 */
	public function get_data( $where = array() ) {
		return $this;
	}

	/**
	 * This function is to create a customer.
	 *
	 * @param object $customer customer details.
	 * @param string $email email.
	 * @param string $password password.
	 * @return mixed
	 */
	public static function mo_saml_create_customer( $customer, $email, $password ) {

		$customer_key = json_decode( $customer->create_customer( $email, $password ), true );
		if ( ! is_null( $customer_key ) ) {
			$response = array();
			if ( strcasecmp( $customer_key['status'], 'CUSTOMER_USERNAME_ALREADY_EXISTS' ) === 0 ) {
				$api_response       = self::mo_saml_get_current_customer( $customer );
				$response['status'] = $api_response ? 'success' : 'error';
			} elseif ( strcasecmp( $customer_key['status'], 'SUCCESS' ) === 0 ) {
				self::mo_saml_update_customer_details( $customer_key );
				$response['status'] = 'success';
			}
			return $response;
		}
		return false;
	}

	/**
	 * This function is to get current customer details.
	 *
	 * @param object $customer customer details.
	 * @return mixed
	 */
	public static function mo_saml_get_current_customer( $customer ) {

		$content = $customer->get_customer_key();

		if ( ! is_null( $content ) ) {
			$customer_key = json_decode( $content, true );

			if ( json_last_error() !== JSON_ERROR_NONE ) {
				Error_Success_Message::show_admin_notice( 'You already have an account with miniOrange. Please enter a valid password.' );
				$response['status'] = 'error';
				return $response;
			}

			self::mo_saml_update_customer_details( $customer_key );
			$response['status'] = 'success';
			return $response;
		}
		return false;
	}

	/**
	 * This function is to update customer details.
	 *
	 * @param array $customer_key array of customer details.
	 * @return void
	 */
	public static function mo_saml_update_customer_details( $customer_key ) {

		$save_array                           = array();
		$save_array['mo_saml_customer_key']   = $customer_key['id'];
		$save_array['mo_saml_api_key']        = $customer_key['apiKey'];
		$save_array['mo_saml_admin_password'] = '';

		Error_Success_Message::show_admin_notice( 'Customer created successfully.', 'SUCCESS' );
	}
}
