<?php
	/** miniOrange SCIM User Provisioner plugin allows User Provisioning to Wordpress using SCIM standard.
	 * Copyright (C) 2015  miniOrange
	 *
	 * This program is free software: you can redistribute it and/or modify
	 * it under the terms of the GNU General Public License as published by
	 * the Free Software Foundation, either version 3 of the License, or
	 * (at your option) any later version.
	 *
	 * This program is distributed in the hope that it will be useful,
	 * but WITHOUT ANY WARRANTY; without even the implied warranty of
	 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	 * GNU General Public License for more details.
	 *
	 * You should have received a copy of the GNU General Public License
	 * along with this program.  If not, see <http://www.gnu.org/licenses/>
	 * @package         miniOrange SCIM User Provisioner
	 * @license        http://www.gnu.org/copyleft/gpl.html GNU/GPL, see LICENSE.php
	 */

	/**
	 * This library is miniOrange Authentication Service.
	 *
	 * Contains Request Calls to Customer service.
	 */
	class CustomerUp{
		public $email;
		public $phone;

		private $defaultCustomerKey = "16555";
		private $defaultApiKey = "fFd2XcvTGDemZvbw1bcUesNJWEqKbbUq";

		function create_customer() {
			$url = get_site_option( 'mo_scim_up_host_name' ) . '/moas/rest/customer/add';

			$ch           = curl_init( $url );
			$current_user = wp_get_current_user();
			$this->email  = get_site_option( 'mo_scim_up_admin_email' );
			$this->phone  = get_site_option( 'mo_scim_up_admin_phone' );
			$password     = get_site_option( 'mo_scim_up_admin_password' );
			$first_name   = get_site_option( 'mo_scim_up_admin_first_name' );
			$last_name    = get_site_option( 'mo_scim_up_admin_last_name' );
			$company      = get_site_option( 'mo_scim_up_admin_company' );

			$fields       = array(
				'companyName'    => $company,
				'areaOfInterest' => 'WP miniOrange SCIM User Provisioner Plugin',
				'firstname'      => $first_name,
				'lastname'       => $last_name,
				'email'          => $this->email,
				'phone'          => $this->phone,
				'password'       => $password
			);
			$field_string = json_encode( $fields );

			curl_setopt( $ch,CURLOPT_FOLLOWLOCATION,true );
			curl_setopt( $ch,CURLOPT_ENCODING,"" );
			curl_setopt( $ch,CURLOPT_RETURNTRANSFER,true );
			curl_setopt( $ch,CURLOPT_AUTOREFERER,true );
			curl_setopt( $ch,CURLOPT_SSL_VERIFYPEER,false );
			curl_setopt( $ch,CURLOPT_SSL_VERIFYHOST,false ); // required for https urls

			curl_setopt( $ch,CURLOPT_MAXREDIRS,10 );
			curl_setopt( $ch,CURLOPT_HTTPHEADER,array(
				'Content-Type: application/json',
				'charset: UTF - 8',
				'Authorization: Basic'
			) );
			curl_setopt( $ch,CURLOPT_POST,true );
			curl_setopt( $ch,CURLOPT_POSTFIELDS,$field_string );
			$proxy_host = get_site_option( "mo_proxy_host" );
			if ( ! empty( $proxy_host ) ) {
				curl_setopt( $ch,CURLOPT_PROXY,get_site_option( "mo_proxy_host" ) );
				curl_setopt( $ch,CURLOPT_PROXYPORT,get_site_option( "mo_proxy_port" ) );
				curl_setopt( $ch,CURLOPT_HTTPAUTH,CURLAUTH_BASIC );
				curl_setopt( $ch,CURLOPT_PROXYUSERPWD,get_site_option( "mo_proxy_username" ) . ':' . get_site_option( "mo_proxy_password" ) );
			}

			$content = curl_exec( $ch );

			if ( curl_errno( $ch ) ) {
				echo 'Request Error:' . curl_error( $ch );
				exit();
			}

			curl_close( $ch );

			return $content;
		}

		function get_customer_key() {
			$url   = get_site_option( 'mo_scim_up_host_name' ) . "/moas/rest/customer/key";
			$ch    = curl_init( $url );
			$email = get_site_option( "mo_scim_up_admin_email" );

			$password = get_site_option( "mo_scim_up_admin_password" );

			$fields       = array( 'email' => $email,'password' => $password );
			$field_string = json_encode( $fields );

			curl_setopt( $ch,CURLOPT_FOLLOWLOCATION,true );
			curl_setopt( $ch,CURLOPT_ENCODING,"" );
			curl_setopt( $ch,CURLOPT_RETURNTRANSFER,true );
			curl_setopt( $ch,CURLOPT_AUTOREFERER,true );
			curl_setopt( $ch,CURLOPT_SSL_VERIFYPEER,false );
			curl_setopt( $ch,CURLOPT_SSL_VERIFYHOST,false ); // required for https urls

			curl_setopt( $ch,CURLOPT_MAXREDIRS,10 );
			curl_setopt( $ch,CURLOPT_HTTPHEADER,array(
				'Content-Type: application/json',
				'charset: UTF - 8',
				'Authorization: Basic'
			) );
			curl_setopt( $ch,CURLOPT_POST,true );
			curl_setopt( $ch,CURLOPT_POSTFIELDS,$field_string );
			$proxy_host = get_site_option( "mo_proxy_host" );
			if ( ! empty( $proxy_host ) ) {
				curl_setopt( $ch,CURLOPT_PROXY,get_site_option( "mo_proxy_host" ) );
				curl_setopt( $ch,CURLOPT_PROXYPORT,get_site_option( "mo_proxy_port" ) );
				curl_setopt( $ch,CURLOPT_HTTPAUTH,CURLAUTH_BASIC );
				curl_setopt( $ch,CURLOPT_PROXYUSERPWD,get_site_option( "mo_proxy_username" ) . ':' . get_site_option( "mo_proxy_password" ) );
			}

			$content = curl_exec( $ch );
			if ( curl_errno( $ch ) ) {
				echo 'Request Error:' . curl_error( $ch );
				exit();
			}

			curl_close( $ch );

			return $content;
		}

		function check_customer() {
			$url   = get_site_option( 'mo_scim_up_host_name' ) . "/moas/rest/customer/check-if-exists";
			$ch    = curl_init( $url );
			$email = get_site_option( "mo_scim_up_admin_email" );

			$fields       = array( 'email' => $email );
			$field_string = json_encode( $fields );

			curl_setopt( $ch,CURLOPT_FOLLOWLOCATION,true );
			curl_setopt( $ch,CURLOPT_ENCODING,"" );
			curl_setopt( $ch,CURLOPT_RETURNTRANSFER,true );
			curl_setopt( $ch,CURLOPT_AUTOREFERER,true );
			curl_setopt( $ch,CURLOPT_SSL_VERIFYPEER,false );
			curl_setopt( $ch,CURLOPT_SSL_VERIFYHOST,false ); // required for https urls

			curl_setopt( $ch,CURLOPT_MAXREDIRS,10 );
			curl_setopt( $ch,CURLOPT_HTTPHEADER,array(
				'Content-Type: application/json',
				'charset: UTF - 8',
				'Authorization: Basic'
			) );
			curl_setopt( $ch,CURLOPT_POST,true );
			curl_setopt( $ch,CURLOPT_POSTFIELDS,$field_string );
			$proxy_host = get_site_option( "mo_proxy_host" );
			if ( ! empty( $proxy_host ) ) {
				curl_setopt( $ch,CURLOPT_PROXY,get_site_option( "mo_proxy_host" ) );
				curl_setopt( $ch,CURLOPT_PROXYPORT,get_site_option( "mo_proxy_port" ) );
				curl_setopt( $ch,CURLOPT_HTTPAUTH,CURLAUTH_BASIC );
				curl_setopt( $ch,CURLOPT_PROXYUSERPWD,get_site_option( "mo_proxy_username" ) . ':' . get_site_option( "mo_proxy_password" ) );
			}

			$content = curl_exec( $ch );
			if ( curl_errno( $ch ) ) {
				echo 'Request Error:' . curl_error( $ch );
				exit();
			}
			curl_close( $ch );

			return $content;
		}

		function check_customer_ln() {
			$url                 = get_site_option( 'mo_scim_up_host_name' ) . '/moas/rest/customer/license';
			$ch                  = curl_init( $url );
			$customerKey         = get_site_option( 'mo_scim_up_admin_customer_key' );
			$apiKey              = get_site_option( 'mo_scim_up_admin_api_key' );
			$currentTimeInMillis = round( microtime( true ) * 1000 );
			$stringToHash        = $customerKey . number_format( $currentTimeInMillis,0,'','' ) . $apiKey;
			$hashValue           = hash( "sha512",$stringToHash );
			$customerKeyHeader   = "Customer-Key: " . $customerKey;
			$timestampHeader     = "Timestamp: " . $currentTimeInMillis;
			$authorizationHeader = "Authorization: " . $hashValue;
			$fields              = '';
			$fields              = array(
				'customerId'      => $customerKey,
				'applicationName' => 'wp_scim_user_provisioning_plan'
			);
			$field_string        = json_encode( $fields );
			curl_setopt( $ch,CURLOPT_FOLLOWLOCATION,true );
			curl_setopt( $ch,CURLOPT_ENCODING,"" );
			curl_setopt( $ch,CURLOPT_RETURNTRANSFER,true );
			curl_setopt( $ch,CURLOPT_AUTOREFERER,true );
			curl_setopt( $ch,CURLOPT_SSL_VERIFYPEER,false );
			curl_setopt( $ch,CURLOPT_SSL_VERIFYHOST,false );  # required for https urls
			curl_setopt( $ch,CURLOPT_MAXREDIRS,10 );
			curl_setopt( $ch,CURLOPT_HTTPHEADER,array(
				"Content-Type: application/json",
				$customerKeyHeader,
				$timestampHeader,
				$authorizationHeader
			) );
			curl_setopt( $ch,CURLOPT_POST,true );
			curl_setopt( $ch,CURLOPT_POSTFIELDS,$field_string );
			curl_setopt( $ch,CURLOPT_CONNECTTIMEOUT,5 );
			curl_setopt( $ch,CURLOPT_TIMEOUT,20 );
			$proxy_host = get_site_option( "mo_proxy_host" );
			if ( ! empty( $proxy_host ) ) {
				curl_setopt( $ch,CURLOPT_PROXY,get_site_option( "mo_proxy_host" ) );
				curl_setopt( $ch,CURLOPT_PROXYPORT,get_site_option( "mo_proxy_port" ) );
				curl_setopt( $ch,CURLOPT_HTTPAUTH,CURLAUTH_BASIC );
				curl_setopt( $ch,CURLOPT_PROXYUSERPWD,get_site_option( "mo_proxy_username" ) . ':' . get_site_option( "mo_proxy_password" ) );
			}
			$content = curl_exec( $ch );
			if ( curl_errno( $ch ) ) {
				return false;
			}
			curl_close( $ch );

			return $content;
		}

		function mo_scim_up_vl( $code,$active ) {
			$url = "";
			if ( $active ) {
				$url = get_site_option( 'mo_scim_up_host_name' ) . '/moas/api/backupcode/check';
			} else {
				$url = get_site_option( 'mo_scim_up_host_name' ) . '/moas/api/backupcode/verify';
			}

			$ch = curl_init( $url );

			/* The customer Key provided to you */
			$customerKey = get_site_option( 'mo_scim_up_admin_customer_key' );

			/* The customer API Key provided to you */
			$apiKey = get_site_option( 'mo_scim_up_admin_api_key' );

			/* Current time in milliseconds since midnight, January 1, 1970 UTC. */
			$currentTimeInMillis = round( microtime( true ) * 1000 );

			/* Creating the Hash using SHA-512 algorithm */
			$stringToHash = $customerKey . number_format( $currentTimeInMillis,0,'','' ) . $apiKey;
			$hashValue    = hash( "sha512",$stringToHash );

			$customerKeyHeader   = "Customer-Key: " . $customerKey;
			$timestampHeader     = "Timestamp: " . number_format( $currentTimeInMillis,0,'','' );
			$authorizationHeader = "Authorization: " . $hashValue;

			$fields = '';

			// *check for otp over sms/email

			$fields = array(
				'code'             => $code,
				'customerKey'      => $customerKey,
				'additionalFields' => array( 'field1' => home_url() )

			);

			$field_string = json_encode( $fields );

			curl_setopt( $ch,CURLOPT_FOLLOWLOCATION,true );
			curl_setopt( $ch,CURLOPT_ENCODING,"" );
			curl_setopt( $ch,CURLOPT_RETURNTRANSFER,true );
			curl_setopt( $ch,CURLOPT_AUTOREFERER,true );
			curl_setopt( $ch,CURLOPT_SSL_VERIFYPEER,false ); // required for https urls
			curl_setopt( $ch,CURLOPT_SSL_VERIFYHOST,false );
			curl_setopt( $ch,CURLOPT_MAXREDIRS,10 );
			curl_setopt( $ch,CURLOPT_HTTPHEADER,array(
				"Content-Type: application/json",
				$customerKeyHeader,
				$timestampHeader,
				$authorizationHeader
			) );
			curl_setopt( $ch,CURLOPT_POST,true );
			curl_setopt( $ch,CURLOPT_POSTFIELDS,$field_string );
			curl_setopt( $ch,CURLOPT_CONNECTTIMEOUT,5 );
			curl_setopt( $ch,CURLOPT_TIMEOUT,20 );
			$proxy_host = get_site_option( "mo_proxy_host" );
			if ( ! empty( $proxy_host ) ) {
				curl_setopt( $ch,CURLOPT_PROXY,get_site_option( "mo_proxy_host" ) );
				curl_setopt( $ch,CURLOPT_PROXYPORT,get_site_option( "mo_proxy_port" ) );
				curl_setopt( $ch,CURLOPT_HTTPAUTH,CURLAUTH_BASIC );
				curl_setopt( $ch,CURLOPT_PROXYUSERPWD,get_site_option( "mo_proxy_username" ) . ':' . get_site_option( "mo_proxy_password" ) );
			}
			$content = curl_exec( $ch );

			if ( curl_errno( $ch ) ) {
				echo 'Request Error:' . curl_error( $ch );
				exit ();
			}

			curl_close( $ch );

			return $content;
		}

		function submit_contact_us( $email,$phone,$query ) {
			$current_user = wp_get_current_user();
			$query        = '[WP SCIM User Provisioner Plugin] ' . $query;
			$fields       = array(
				'firstName' => $current_user->user_firstname,
				'lastName'  => $current_user->user_lastname,
				'company'   => $_SERVER ['SERVER_NAME'],
				'email'     => $email,
				'phone'     => $phone,
				'query'     => $query
			);
			$field_string = json_encode( $fields );

			$url = get_site_option( 'mo_scim_up_host_name' ) . '/moas/rest/customer/contact-us';

			$ch = curl_init( $url );
			curl_setopt( $ch,CURLOPT_FOLLOWLOCATION,true );
			curl_setopt( $ch,CURLOPT_ENCODING,"" );
			curl_setopt( $ch,CURLOPT_RETURNTRANSFER,true );
			curl_setopt( $ch,CURLOPT_AUTOREFERER,true );
			curl_setopt( $ch,CURLOPT_SSL_VERIFYPEER,false );
			curl_setopt( $ch,CURLOPT_SSL_VERIFYHOST,false ); // required for https urls
			curl_setopt( $ch,CURLOPT_MAXREDIRS,10 );
			curl_setopt( $ch,CURLOPT_HTTPHEADER,array(
				'Content-Type: application/json',
				'charset: UTF-8',
				'Authorization: Basic'
			) );
			curl_setopt( $ch,CURLOPT_POST,true );
			curl_setopt( $ch,CURLOPT_POSTFIELDS,$field_string );
			$proxy_host = get_site_option( "mo_proxy_host" );
			if ( ! empty( $proxy_host ) ) {
				curl_setopt( $ch,CURLOPT_PROXY,get_site_option( "mo_proxy_host" ) );
				curl_setopt( $ch,CURLOPT_PROXYPORT,get_site_option( "mo_proxy_port" ) );
				curl_setopt( $ch,CURLOPT_HTTPAUTH,CURLAUTH_BASIC );
				curl_setopt( $ch,CURLOPT_PROXYUSERPWD,get_site_option( "mo_proxy_username" ) . ':' . get_site_option( "mo_proxy_password" ) );
			}

			$content = curl_exec( $ch );

			if ( curl_errno( $ch ) ) {
				echo 'Request Error:' . curl_error( $ch );

				return false;
			}

			// echo " Content: " . $content;

			curl_close( $ch );

			return true;
		}

		function mo_scim_up_forgot_password( $email ) {
			$url = get_site_option( 'mo_scim_up_host_name' ) . '/moas/rest/customer/password-reset';
			$ch  = curl_init( $url );

			/* The customer Key provided to you */
			$customerKey = get_site_option( 'mo_scim_up_admin_customer_key' );

			/* The customer API Key provided to you */
			$apiKey = get_site_option( 'mo_scim_up_admin_api_key' );

			/* Current time in milliseconds since midnight, January 1, 1970 UTC. */
			$currentTimeInMillis = round( microtime( true ) * 1000 );

			/* Creating the Hash using SHA-512 algorithm */
			$stringToHash = $customerKey . number_format( $currentTimeInMillis,0,'','' ) . $apiKey;
			$hashValue    = hash( "sha512",$stringToHash );

			$customerKeyHeader   = "Customer-Key: " . $customerKey;
			$timestampHeader     = "Timestamp: " . number_format( $currentTimeInMillis,0,'','' );
			$authorizationHeader = "Authorization: " . $hashValue;

			$fields = '';

			// *check for otp over sms/email
			$fields = array( 'email' => $email );

			$field_string = json_encode( $fields );

			curl_setopt( $ch,CURLOPT_FOLLOWLOCATION,true );
			curl_setopt( $ch,CURLOPT_ENCODING,"" );
			curl_setopt( $ch,CURLOPT_RETURNTRANSFER,true );
			curl_setopt( $ch,CURLOPT_AUTOREFERER,true );
			curl_setopt( $ch,CURLOPT_SSL_VERIFYPEER,false );
			curl_setopt( $ch,CURLOPT_SSL_VERIFYHOST,false ); // required for https urls

			curl_setopt( $ch,CURLOPT_MAXREDIRS,10 );
			curl_setopt( $ch,CURLOPT_HTTPHEADER,array(
				"Content-Type: application/json",
				$customerKeyHeader,
				$timestampHeader,
				$authorizationHeader
			) );
			curl_setopt( $ch,CURLOPT_POST,true );
			curl_setopt( $ch,CURLOPT_POSTFIELDS,$field_string );
			curl_setopt( $ch,CURLOPT_CONNECTTIMEOUT,5 );
			curl_setopt( $ch,CURLOPT_TIMEOUT,20 );
			$proxy_host = get_site_option( "mo_proxy_host" );
			if ( ! empty( $proxy_host ) ) {
				curl_setopt( $ch,CURLOPT_PROXY,get_site_option( "mo_proxy_host" ) );
				curl_setopt( $ch,CURLOPT_PROXYPORT,get_site_option( "mo_proxy_port" ) );
				curl_setopt( $ch,CURLOPT_HTTPAUTH,CURLAUTH_BASIC );
				curl_setopt( $ch,CURLOPT_PROXYUSERPWD,get_site_option( "mo_proxy_username" ) . ':' . get_site_option( "mo_proxy_password" ) );
			}

			$content = curl_exec( $ch );

			if ( curl_errno( $ch ) ) {
				if ( curl_errno( $ch ) ) {
					if ( $this->is_connection_issue( curl_errno( $ch ) ) ) {
						wp_die( "There was an issue connection to Internet. Check if your firewall is allowing outbound connection to port 443.<br><br>In case you are using proxy, go to proxy tab in plugin and configure proxy settings." );
					}

					echo 'Request Error:' . curl_error( $ch );
					exit ();
				}
				echo 'Request Error:' . curl_error( $ch );
				exit();
			}

			curl_close( $ch );

			return $content;
		}
	}

	function mo_scim_up_update_status() {
		$url                 = get_site_option( 'mo_scim_up_host_name' ) . '/moas/api/backupcode/updatestatus';
		$ch                  = curl_init( $url );
		$customerKey         = get_site_option( 'mo_scim_up_admin_customer_key' );
		$apiKey              = get_site_option( 'mo_scim_up_admin_api_key' );
		$currentTimeInMillis = round( microtime( true ) * 1000 );
		$stringToHash        = $customerKey . number_format( $currentTimeInMillis,0,'','' ) . $apiKey;
		$hashValue           = hash( "sha512",$stringToHash );
		$customerKeyHeader   = "Customer-Key: " . $customerKey;
		$timestampHeader     = "Timestamp: " . number_format( $currentTimeInMillis,0,'','' );
		$authorizationHeader = "Authorization: " . $hashValue;
		$key                 = get_site_option( 'mo_scim_up_customer_token' );
		$code                = AESEncryptionInPR::decrypt_data( get_site_option( 'mo_scim_up_lk' ),$key );
		$fields              = array(
			'code'             => $code,
			'customerKey'      => $customerKey,
			'additionalFields' => array( 'field1' => home_url() )
		);
		$field_string        = json_encode( $fields );
		curl_setopt( $ch,CURLOPT_FOLLOWLOCATION,true );
		curl_setopt( $ch,CURLOPT_ENCODING,"" );
		curl_setopt( $ch,CURLOPT_RETURNTRANSFER,true );
		curl_setopt( $ch,CURLOPT_AUTOREFERER,true );
		curl_setopt( $ch,CURLOPT_SSL_VERIFYPEER,false );
		curl_setopt( $ch,CURLOPT_SSL_VERIFYHOST,false );// required for https urls
		curl_setopt( $ch,CURLOPT_MAXREDIRS,10 );
		curl_setopt( $ch,CURLOPT_HTTPHEADER,array(
			"Content-Type: application/json",
			$customerKeyHeader,
			$timestampHeader,
			$authorizationHeader
		) );
		curl_setopt( $ch,CURLOPT_POST,true );
		curl_setopt( $ch,CURLOPT_POSTFIELDS,$field_string );
		curl_setopt( $ch,CURLOPT_CONNECTTIMEOUT,5 );
		curl_setopt( $ch,CURLOPT_TIMEOUT,20 );
		$proxy_host = get_site_option( "mo_proxy_host" );
		if ( ! empty( $proxy_host ) ) {
			curl_setopt( $ch,CURLOPT_PROXY,get_site_option( "mo_proxy_host" ) );
			curl_setopt( $ch,CURLOPT_PROXYPORT,get_site_option( "mo_proxy_port" ) );
			curl_setopt( $ch,CURLOPT_HTTPAUTH,CURLAUTH_BASIC );
			curl_setopt( $ch,CURLOPT_PROXYUSERPWD,get_site_option( "mo_proxy_username" ) . ':' . get_site_option( "mo_proxy_password" ) );
		}
		$content = curl_exec( $ch );
		if ( curl_errno( $ch ) ) {
			echo 'Request Error:' . curl_error( $ch );
			exit ();
		}
		curl_close( $ch );

		return $content;
	}
