<?php
/** This file takes care of making API requests for interacting with the customer’s miniOrange account.
 *
 * @package     miniorange-saml-20-single-sign-on
 */

namespace MOSAML\SRC\Classes;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\SRC\Constant\Constants;
use MOSAML\SRC\Constant\URL_Constants;
use MOSAML\SRC\Utils\Utility;
use MOSAML\SRC\Utils\Error_Success_Message;

/**
 * This class Mo_SAML_Customer contains functions to handle all the customer related functionalities like sending support query, feedback.
 */
class Mo_Customer {

	/**
	 * Customer Email.
	 *
	 * @var      string $email Customer's Email.
	 */
	public $email;

	/**
	 * Customer API Key.
	 * Initial values are hardcoded to support the miniOrange framework to generate OTP for email.
	 * We need the default value for creating the first time,
	 * As we don't have the Default keys available before registering the user to our server.
	 * This default values are only required for sending an One Time Passcode at the user provided email address.
	 *
	 * @var      string $default_api_key Customer's Customer Key.
	 */
	private $default_api_key = 'fFd2XcvTGDemZvbw1bcUesNJWEqKbbUq';

	/**
	 * Default Customer Key to send feedback for the plugin.
	 *
	 * @var      string $default_customer_key Customer's Customer Key.
	 */
	private $default_customer_key = '16555';

	/**
	 * Function to verify customer login and save details and show the admin notices accordingly.
	 */
	public function verify_customer() {

		Utility::validate_curl_extension();

		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- Nonce verification is done already.
		if ( empty( $_POST ['email'] ) || empty( $_POST ['password'] ) ) {
			Error_Success_Message::show_admin_notice( 'All the fields are required. Please enter valid entries.' );
			return;
		}

		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- Nonce verification is done already.
		$email    = sanitize_email( wp_unslash( $_POST['email'] ) );
		$password = Utility::sanitize_post_data( 'password' );

		$login_response = $this->get_customer_key( $email, $password );
		if ( empty( $login_response ) ) {
			return;
		}

		$customer_key = json_decode( $login_response, true );
		if ( json_last_error() === JSON_ERROR_NONE ) {
			update_option( 'mo_saml_admin_customer_key', $customer_key['id'] );
			update_option( 'mo_saml_admin_api_key', $customer_key['apiKey'] );
			update_option( 'mo_saml_customer_token', $customer_key['token'] );
			if ( ! empty( $customer_key['phone'] ) ) {
				update_option( 'mo_saml_admin_phone', $customer_key['phone'] );
			}
			delete_option( 'mo_saml_verify_customer' );
			Error_Success_Message::show_admin_notice( 'Customer logged-in successfully', 'SUCCESS' );
		}

		Error_Success_Message::show_admin_notice( 'Invalid username or password. Please try again.' );
	}

	/**
	 * Function to remove account details and show the admin notices accordingly.
	 */
	public function remove_account() {
		do_action( 'mosaml_flush_cache_internal' );
		delete_option( 'mo_saml_admin_customer_key' );
		delete_option( 'mo_saml_admin_api_key' );
		delete_option( 'mo_saml_tla' );
		delete_option( 'mo_saml_customer_token' );
		delete_option( 'mo_saml_admin_phone' );
		delete_option( 'mo_saml_verify_customer' );
		Error_Success_Message::show_admin_notice( 'Customer logged out successfully', 'SUCCESS' );
	}

	/**
	 * This function is used for creating customer by making a call to the /rest/customer/add endpoint.
	 *
	 * @param string $email Customer's email.
	 * @param string $password Customer's password.
	 *
	 * @return array $response Response of the API call for creating Customer.
	 */
	public function create_customer( $email, $password ) {
		$url         = URL_Constants::CUSTOMER_ADD_URL;
		$this->email = $email;
		$password    = $password;

		$fields       = array(
			'areaOfInterest' => 'WP miniOrange SAML 2.0 SSO Plugin',
			'email'          => $this->email,
			'password'       => $password,
		);
		$field_string = wp_json_encode( $fields );

		$headers = $this->get_basic_headers();

		$args     = array(
			'method'      => 'POST',
			'body'        => $field_string,
			'timeout'     => '10',
			'redirection' => '5',
			'httpversion' => '1.0',
			'blocking'    => true,
			'headers'     => $headers,
		);
		$response = self::mo_saml_wp_remote_post( $url, $args );
		return $response;
	}

	/**
	 * This function is used for getting customer key.
	 *
	 * @param string $email Customer's email.
	 * @param string $password Customer's password.
	 *
	 * @return array|string $response Response of the API call for fetching Customer key by making a call to the /rest/customer/key endpoint.
	 */
	public function get_customer_key( $email, $password ) {
		$url = URL_Constants::CUSTOMER_KEY_URL;

		$fields       = array(
			'email'    => $email,
			'password' => $password,
		);
		$field_string = wp_json_encode( $fields );

		$headers = $this->get_basic_headers();

		$args     = array(
			'method'      => 'POST',
			'body'        => $field_string,
			'timeout'     => '10',
			'redirection' => '5',
			'httpversion' => '1.0',
			'blocking'    => true,
			'headers'     => $headers,
		);
		$response = self::mo_saml_wp_remote_post( $url, $args );
		return $response;
	}

	/**
	 * This function is used for checking if customer exists by making a call to the /rest/customer/check-if-exists endpoint.
	 *
	 * @param string $email Customer's email.
	 *
	 * @return string $response Response of the API call for customer validity.
	 */
	public function check_customer( $email ) {
		$url = URL_Constants::CUSTOMER_CHECK_EXISTS_URL;

		$fields       = array(
			'email' => $email,
		);
		$field_string = wp_json_encode( $fields );

		$headers = $this->get_basic_headers();

		$args     = array(
			'method'      => 'POST',
			'body'        => $field_string,
			'timeout'     => '10',
			'redirection' => '5',
			'httpversion' => '1.0',
			'blocking'    => true,
			'headers'     => $headers,
		);
		$response = self::mo_saml_wp_remote_post( $url, $args );
		return $response;
	}

	/**
	 * Get basic headers.
	 *
	 * @return array
	 */
	public function get_basic_headers() {
		return array(
			'Content-Type'  => 'application/json',
			'charset'       => 'UTF-8',
			'Authorization' => 'Basic',
		);
	}


	/**
	 * This function is used to get time when the Support query or the demo request has been raised by making a call to the /rest/mobile/get-timestamp endpoint.
	 *
	 * @return string $response This is time when query was raised.
	 */
	public function mo_saml_get_timestamp() {
		$url      = URL_Constants::MOBILE_GET_TIMESTAMP_URL;
		$response = self::mo_saml_wp_remote_post( $url );
		return $response;
	}

	/**
	 * Makes an HTTP request to given url using post method and returns its response.
	 *
	 * @param  string $url endpoint where the HTTP request is made.
	 * @param  array  $args Request arguments.
	 * @return string
	 */
	public static function mo_saml_wp_remote_post( $url, $args = array() ) {
		$response = wp_remote_post( $url, $args );
		if ( ! is_wp_error( $response ) ) {
			return $response['body'];
		} else {
			Error_Success_Message::show_admin_notice( 'Unable to connect to the Internet. Please try again.' );
			return null;
		}
	}

	/**
	 * Check if customer is verified.
	 *
	 * @return bool
	 */
	public static function is_account_verified() {
		$customer_key = get_option( 'mo_saml_admin_customer_key' );
		$email        = get_option( 'mo_saml_admin_email' );
		if ( empty( $customer_key ) || empty( $email ) ) {
			return false;
		} else {
			return true;
		}
	}

	/**
	 * This function is used for sending the query for demo requests and feedback for the plugin by making a call to the /api/notify/send endpoint.
	 *
	 * @param string $email        Customer's Email.
	 * @param string $phone        Customer's Phone.
	 * @param string $message      Customer's Message.
	 *
	 * @return string $response     Response of the API call for demo request and feedback.
	 */
	public function mo_saml_send_email_alert( $email, $phone, $message ) {
		$url = URL_Constants::NOTIFY_SEND_URL;

		$customer_key = ! empty( get_option( 'mo_saml_admin_customer_key' ) ) ? get_option( 'mo_saml_admin_customer_key' ) : $this->default_customer_key;
		$api_key      = $this->default_api_key;

		$current_time_in_millis = $this->mo_saml_get_timestamp();
		$current_time_in_millis = number_format( $current_time_in_millis, 0, '', '' );
		$string_to_hash         = $customer_key . $current_time_in_millis . $api_key;
		$hash_value             = hash( 'sha512', $string_to_hash );
		$from_email             = 'no-reply@xecurify.com';
		$plan_name              = array(
			'1' => 'WP SAML SP SSO Free Plugin',
			'2' => 'WP SAML SP SSO Standard Plugin',
			'3' => 'WP SAML SP SSO Premium Plugin',
			'4' => 'WP SAML SP SSO Enterprise Plugin',
		);

		$subject  = 'Feedback: ' . $plan_name[ MOSAML_VERSION ] . ' v' . Constants::VERSION_NUMBER[ MOSAML_VERSION ];
		$site_url = site_url();

		$current_user = wp_get_current_user();

		$query = '[ WordPress SAML SP SSO Plugin: ]: ' . $message;

		if ( isset( $_SERVER['SERVER_NAME'] ) ) {
			$server_name = sanitize_text_field( wp_unslash( $_SERVER['SERVER_NAME'] ) );
		} else {
			$server_name = '';
		}

		$content = '<div>Hello, <br><br>First Name :' . esc_html( $current_user->user_firstname ) . '<br><br>Last  Name :' . esc_html( $current_user->user_lastname ) . '   <br><br>Company :<a href="' . esc_html( $server_name ) . '" target="_blank" >' . esc_html( $server_name ) . '</a><br><br>Phone Number :' . esc_html( $phone ) . '<br><br>Customer Key :' . esc_html( $customer_key ) . '<br><br>Email :<a href="mailto:' . esc_attr( $email ) . '" target="_blank">' . esc_html( $email ) . '</a><br><br>Query :' . wp_kses( $query, array( 'br' => array() ) ) . '</div>';

		if ( isset( $_SERVER['SERVER_NAME'] ) ) {
			$server_name = sanitize_text_field( wp_unslash( $_SERVER['SERVER_NAME'] ) );
		} else {
			$server_name = '';
		}

		$fields       = array(
			'customerKey' => $customer_key,
			'sendEmail'   => true,
			'email'       => array(
				'customerKey' => $customer_key,
				'fromEmail'   => $from_email,
				'fromName'    => 'Xecurify',
				'toEmail'     => 'info@xecurify.com',
				'toName'      => 'samlsupport@xecurify.com',
				'bccEmail'    => 'samlsupport@xecurify.com',
				'subject'     => $subject,
				'content'     => $content,
			),
		);
		$field_string = wp_json_encode( $fields );

		$headers  = array(
			'Content-Type'  => 'application/json',
			'Customer-Key'  => $customer_key,
			'Timestamp'     => $current_time_in_millis,
			'Authorization' => $hash_value,
		);
		$args     = array(
			'method'      => 'POST',
			'body'        => $field_string,
			'timeout'     => '10',
			'redirection' => '5',
			'httpversion' => '1.0',
			'blocking'    => true,
			'headers'     => $headers,
		);
		$response = self::mo_saml_wp_remote_post( $url, $args );
		return $response;
	}

	/**
	 * Submit contact-us request to miniOrange support.
	 *
	 * @param string $email User email.
	 * @param string $phone User phone.
	 * @param string $query Support query.
	 * @param bool   $deactivate Whether this request is for deactivation feedback.
	 * @return array|\WP_Error Response from remote request.
	 */
	public function submit_contact_us( $email, $phone, $query, $deactivate = false ) {
		$url             = URL_Constants::CUSTOMER_CONTACT_US_URL;
		$current_user    = wp_get_current_user();
		$customer_id     = get_option( 'mo_saml_admin_customer_key' );
		$plan_name       = array(
			'1' => 'WP SAML SP SSO Free Plugin',
			'2' => 'WP SAML SP SSO Standard Plugin',
			'3' => 'WP SAML SP SSO Premium Plugin',
			'4' => 'WP SAML SP SSO Enterprise Plugin',
		);
		$deactivate_text = $deactivate ? 'Plugin Deactivation' : '';
		$query           = '[' . $deactivate_text . ' ' . $plan_name[ MOSAML_VERSION ] . ' v' . Constants::VERSION_NUMBER[ MOSAML_VERSION ] . ' ] ' . $query . '<br><br>Customer ID : ' . $customer_id;

		if ( isset( $_SERVER['SERVER_NAME'] ) ) {
			$server_name = sanitize_text_field( wp_unslash( $_SERVER['SERVER_NAME'] ) );
		} else {
			$server_name = '';
		}
		$fields = array(
			'firstName' => $current_user->user_firstname,
			'lastName'  => $current_user->user_lastname,
			'company'   => $server_name,
			'ccEmail'   => 'samlsupport@xecurify.com',
			'email'     => $email,
			'phone'     => $phone,
			'query'     => $query,
		);

		$field_string = wp_json_encode( $fields );
		$headers      = array(
			'Content-Type'  => 'application/json',
			'charset'       => 'UTF-8',
			'Authorization' => 'Basic',
		);

		$args = array(
			'method'      => 'POST',
			'body'        => $field_string,
			'timeout'     => '10',
			'redirection' => '5',
			'httpversion' => '1.0',
			'blocking'    => true,
			'headers'     => $headers,
		);

		$response = self::mo_saml_wp_remote_post( $url, $args );
		return $response;
	}
}
