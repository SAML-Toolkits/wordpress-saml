<?php

	require_once( "mo-scim-user-provisioner-class-customer.php" );
	if ( ! class_exists( "AESEncryptionInPR" ) ) {
		require_once dirname( __FILE__ ) . '/includes/lib/encryption.php';
	}

	function miniorange_save_setting_user_provisioning() {
		$userProv = new scim_user_provisioner_add_on();

		if ( isset( $_POST['option'] ) && $_POST['option'] == 'mo_scim_up_goto_login' ) {
			update_site_option( 'mo_scim_up_verify_customer','true' );
		}
		if ( isset( $_POST['option'] ) && $_POST['option'] == 'generate_new_token_option' ) {
			delete_site_option( 'mo_scim_up_bearer_token' );
			update_site_option( 'mo_scim_up_message','Bearer Token refreshed successfully. Kindly configure your IDP with the new token' );
			$userProv->mo_scim_up_show_success_message();
		}
		if ( isset( $_POST['option'] ) && $_POST['option'] == 'mo_scim_select_idp_option' ) {
			if ( isset( $_POST['mo_scim_idp_name'] ) ) {
				$scim_idp_name = $_POST['mo_scim_idp_name'];
				update_site_option( 'mo_scim_idp_name',$scim_idp_name );
			}
			update_site_option( 'mo_scim_up_message','Configuration Saved Successfully' );
			$userProv->mo_scim_up_show_success_message();
		}
		if ( isset( $_POST['option'] ) && $_POST['option'] == 'mo_scim_up_verify_license' ) {
			$code     = trim( $_POST['mo_scim_up_licence_key'] );
			$customer = new CustomerUp();
			$content  = json_decode( $customer->check_customer_ln(),true );
			if ( strcasecmp( $content['status'],'SUCCESS' ) == 0 ) {
				$content = json_decode( $customer->mo_scim_up_vl( $code,false ),true );
				update_site_option( 'mo_scim_up_vl_check_t',time() );
				if ( strcasecmp( $content['status'],'SUCCESS' ) == 0 ) {
					$key = get_site_option( 'mo_scim_up_customer_token' );
					update_site_option( 'mo_scim_up_lk',AESEncryptionInPR::encrypt_data( $code,$key ) );
					update_site_option( 'mo_scim_up_message','Your license is verified. You can now setup the plugin.' );
					$key = get_site_option( 'mo_scim_up_customer_token' );
					update_site_option( 'mo_scim_up_site_ck_l',AESEncryptionInPR::encrypt_data( "true",$key ) );
					update_site_option( 't_site_status',AESEncryptionInPR::encrypt_data( "false",$key ) );
					$userProv->mo_scim_up_show_success_message();
				} elseif ( strcasecmp( $content['status'],'FAILED' ) == 0 ) {
					if ( strcasecmp( $content['message'],'Code has Expired' ) == 0 ) {
						$url = add_query_arg( array( 'tab' => 'licensing' ),$_SERVER['REQUEST_URI'] );
						update_site_option( 'mo_scim_up_message','License key you have entered has already been used. Please enter a key which has not been used before on any other instance or if you have exausted all your keys then <a href="' . $url . '">Click here</a> to buy more.' );
					} else {
						update_site_option( 'mo_scim_up_message','You have entered an invalid license key. Please enter a valid license key.' );
					}
					$userProv->mo_scim_up_show_error_message();
				} else {
					update_site_option( 'mo_scim_up_message','An error occured while processing your request. Please Try again.' );
					$userProv->mo_scim_up_show_error_message();
				}
			} else {
				$key = get_site_option( 'mo_scim_up_customer_token' );
				update_site_option( 'mo_scim_up_site_ck_l',AESEncryptionInPR::encrypt_data( "false",$key ) );
				$url = add_query_arg( array( 'tab' => 'licensing' ),$_SERVER['REQUEST_URI'] );
				update_site_option( 'mo_scim_up_message','You have not upgraded yet.' );
				$userProv->mo_scim_up_show_error_message();
			}
		}

		if ( isset( $_POST['option'] ) and $_POST['option'] == "mo_scim_up_verify_customer_value" ) {    //register the admin to miniOrange
			//validation and sanitization
			$email    = '';
			$password = '';
			if ( mo_scim_up_check_empty_or_null( $_POST['email'] ) || mo_scim_up_check_empty_or_null( $_POST['password'] ) ) {
				update_site_option( 'mo_scim_up_message','All the fields are required. Please enter valid entries.' );
				$userProv->mo_scim_up_show_error_message();

				return;
			} else {
				$email    = sanitize_email( $_POST['email'] );
				$password = sanitize_text_field( $_POST['password'] );
			}

			update_site_option( 'mo_scim_up_admin_email',$email );
			update_site_option( 'mo_scim_up_admin_password',$password );
			$customer    = new CustomerUp();
			$content     = $customer->get_customer_key();
			$customerKey = json_decode( $content,true );

			if ( json_last_error() == JSON_ERROR_NONE ) {
				update_site_option( 'mo_scim_up_admin_customer_key',$customerKey['id'] );
				update_site_option( 'mo_scim_up_admin_api_key',$customerKey['apiKey'] );
				update_site_option( 'mo_scim_up_customer_token',$customerKey['token'] );
				update_site_option( 'mo_scim_up_admin_phone',$customerKey['phone'] );
				delete_site_option( 'mo_scim_up_admin_password' );
				update_site_option( 'mo_scim_up_message','Customer retrieved successfully' );
				delete_site_option( 'mo_scim_up_verify_customer' );
				$userProv->mo_scim_up_show_success_message();
			} else {
				update_site_option( 'mo_scim_up_message','Invalid username or password. Please try again.' );
				$userProv->mo_scim_up_show_error_message();
			}
		} elseif ( isset( $_POST['option'] ) && $_POST['option'] == "mo_scim_up_contact_us_query_option" ) {
			if ( ! mo_scim_up_is_curl_installed() ) {
				update_site_option( 'mo_scim_up_message','ERROR: PHP cURL extension is not installed or disabled. Query submit failed.' );
				$userProv->mo_scim_up_show_error_message();

				return;
			}

			// Contact Us query
			if ( isset( $_POST['mo_scim_up_contact_us_email'] ) ) {
				$email = $_POST['mo_scim_up_contact_us_email'];
			}
			if ( isset( $_POST['mo_scim_up_contact_us_phone'] ) ) {
				$phone = isset( $_POST['mo_scim_up_contact_us_phone'] );
			}
			if ( isset( $_POST['mo_scim_up_contact_us_query'] ) ) {
				$query = $_POST['mo_scim_up_contact_us_query'];
			}
			$customer = new CustomerUp();
			if ( mo_scim_up_check_empty_or_null( $email ) || mo_scim_up_check_empty_or_null( $query ) ) {
				update_site_option( 'mo_scim_up_message','Please fill up Email and Query fields to submit your query.' );
				$userProv->mo_scim_up_show_error_message();
			} else {
				$submited = $customer->submit_contact_us( $email,$phone,$query );
				if ( $submited == false ) {
					update_site_option( 'mo_scim_up_message','Your query could not be submitted. Please try again.' );
					$userProv->mo_scim_up_show_error_message();
				} else {
					update_site_option( 'mo_scim_up_message','Thanks for getting in touch! We shall get back to you shortly.' );
					$userProv->mo_scim_up_show_success_message();
				}
			}
		}

		if ( isset( $_POST['option'] ) and $_POST['option'] == 'mo_scim_deprovision_user_option' ) {
			if ( isset( $_POST['mo_scim_deprovision_for_admins'] ) and $_POST['mo_scim_deprovision_for_admins'] == 'true' ) {
				update_site_option( 'mo_scim_deprovision_for_admins','true' );
			} else {
				update_site_option( 'mo_scim_deprovision_for_admins','false' );
			}
			if ( isset( $_POST['mo_scim_disable_deprovisioned_users'] ) and $_POST['mo_scim_disable_deprovisioned_users'] == 'true' ) {
				update_site_option( 'mo_scim_user_deprovisioning_mode','deactivate' );
			} else {
				update_site_option( 'mo_scim_user_deprovisioning_mode','delete' );
			}
			if ( isset( $_POST['mo_scim_show_attribute'] ) and $_POST['mo_scim_show_attribute'] == 'true' ) {
				update_site_option( 'mo_scim_show_attribute','true' );
			} else {
				update_site_option( 'mo_scim_show_attribute','false' );
			}
			if ( isset( $_POST['mo_scim_username_error'] ) and $_POST['mo_scim_username_error'] == true ) {
				update_site_option( 'mo_scim_username_error', true );
			} else {
				update_site_option( 'mo_scim_username_error', false );
			}

			update_site_option( 'mo_scim_up_message','Configuration Saved Successfully' );
			$userProv->mo_scim_up_show_success_message();
		} 
		else if( mo_check_option_admin_referer( 'mo_scim_transaction_log' )){
	
			if (isset($_POST['mo_scim_transaction_log']) and $_POST['mo_scim_transaction_log'] == 'on') {
				update_site_option('mo_scim_transaction_log', 'true');
			} else {
				update_site_option('mo_scim_transaction_log', 'false');
			}
			update_site_option( 'mo_scim_up_message','Configuration Saved Successfully' );
			$userProv->mo_scim_up_show_success_message();
		}////////////////////For attribute mapping ///////////////////////

		elseif ( mo_check_option_admin_referer( 'login_widget_scim_attribute_mapping' ) ) {
			$custom_attributes = array();
			$keys              = array();
			$values            = array();
			$attrs_to_display  = array();
			if ( isset( $_POST['mo_scim_custom_attribute_keys'] ) && ! empty( $_POST['mo_scim_custom_attribute_keys'] ) ) {
				$keys = $_POST['mo_scim_custom_attribute_keys'];
			}
			if ( isset( $_POST['mo_scim_custom_attribute_values'] ) && ! empty( $_POST['mo_scim_custom_attribute_values'] ) ) {
				$values = $_POST['mo_scim_custom_attribute_values'];
			}

			$count_keys = count( $keys );

			if ( $count_keys > 0 ) {
				$keys   = array_map( 'htmlspecialchars',$keys );
				$values = array_map( 'htmlspecialchars',$values );
				$index  = 0;
				while ( $index < $count_keys ) {
					if ( isset( $_POST[ 'mo_scim_display_attribute_' . $index ] ) && ! empty( $_POST[ 'mo_scim_display_attribute_' . $index ] ) ) {
						array_push( $attrs_to_display,$index );
					}
					$index ++;
				}
			}

			update_site_option( 'scim_show_user_attribute',$attrs_to_display );
			$custom_attributes = array_combine( $keys,$values );

			// Filter empty values
			$custom_attributes = array_filter( $custom_attributes );

			if ( ! empty( $custom_attributes ) ) {
				// Save the custom attribute mapping if non-empty mapping values are provided
				update_site_option( 'mo_scim_custom_attrs_mapping',$custom_attributes );
			} else {
				// Delete custom attribute mapping if empty mapping is provided
				$custom_attributes = get_site_option( 'mo_scim_custom_attrs_mapping' );
				if ( ! empty( $custom_attributes ) ) {
					delete_site_option( 'mo_scim_custom_attrs_mapping' );
				}
			}

			update_site_option( 'mo_scim_up_message','Attribute Mapping details saved successfully' );
			$userProv->mo_scim_up_show_success_message();
		} elseif ( mo_check_option_admin_referer( 'login_widget_scim_attribute_mapping_buddypress' ) ) {
			$custom_attributes = array();
			$keys              = array();
			$values            = array();
			$attrs_to_display  = array();
			if ( isset( $_POST['mo_scim_custom_attribute_keys_bp'] ) && ! empty( $_POST['mo_scim_custom_attribute_keys_bp'] ) ) {
				$keys = $_POST['mo_scim_custom_attribute_keys_bp'];
			}

			if ( isset( $_POST['mo_scim_custom_attribute_values_bp'] ) && ! empty( $_POST['mo_scim_custom_attribute_values_bp'] ) ) {
				$values = $_POST['mo_scim_custom_attribute_values_bp'];
			}

			$count_keys = count( $keys );

			if ( $count_keys > 0 ) {
				$keys   = array_map( 'htmlspecialchars',$keys );
				$values = array_map( 'htmlspecialchars',$values );
				$index  = 0;
				while ( $index < $count_keys ) {
					if ( isset( $_POST[ 'mo_scim_display_attribute_' . $index ] ) && ! empty( $_POST[ 'mo_scim_display_attribute_' . $index ] ) ) {
						array_push( $attrs_to_display,$index );
					}
					$index ++;
				}
			}

			update_site_option( 'scim_show_user_attribute',$attrs_to_display );
			$custom_attributes = array_combine( $keys,$values );
			// Filter empty values
			$custom_attributes = array_filter( $custom_attributes );

			if ( ! empty( $custom_attributes ) ) {
				// Save the custom attribute mapping if non-empty mapping values are provided
				update_site_option( 'mo_scim_custom_attrs_mapping_buddypress',$custom_attributes );
			} else {
				// Delete custom attribute mapping if empty mapping is provided
				$custom_attributes = get_site_option( 'mo_scim_custom_attrs_mapping_buddypress' );
				if ( ! empty( $custom_attributes ) ) {
					delete_site_option( 'mo_scim_custom_attrs_mapping_buddypress' );
				}
			}

			update_site_option( 'mo_scim_up_message','Buddypress Attribute Mapping details saved successfully' );
			$userProv->mo_scim_up_show_success_message();
		} elseif ( mo_check_option_admin_referer( 'mo_scim_show_attribute' ) ) {
			if ( isset( $_POST["mo_scim_show_attribute"] ) ) {
				update_site_option( 'mo_scim_show_attribute','true' );
			} else {
				update_site_option( 'mo_scim_show_attribute','false' );
			}

			update_site_option( 'mo_scim_up_message','Saved' );
			$userProv->mo_scim_up_show_success_message();
		} elseif ( mo_check_option_admin_referer( 'mo_scim_username_error' ) ) {
			if ( isset( $_POST["mo_scim_username_error"] ) ) {
				update_site_option( 'mo_scim_username_error', true );
			} else {
				update_site_option( 'mo_scim_username_error', false );
			}
			update_site_option( 'mo_scim_up_message','Saved' );
			$userProv->mo_scim_up_show_success_message();
		} elseif ( mo_check_option_admin_referer( 'mo_scim_idp_name' ) ) {
			if ( isset( $_POST['mo_scim_idp_name'] ) && ! empty( $_POST['mo_scim_idp_name'] ) ) {
				$drop_value = $_POST['mo_scim_idp_name'];
				$drop_value = sanitize_text_field( $drop_value );
				update_site_option( 'mo_scim_idp_name',$drop_value );
			}

			update_site_option( 'mo_scim_up_message','Updated Identity Provider' );
			$userProv->mo_scim_up_show_success_message();
		} elseif ( mo_check_option_admin_referer( 'cross_provisioning_save' ) ) {
			$url_token         = array();
			$baseUrl           = array();
			$token             = array();
			$tokens_to_display = array();
			if ( isset( $_POST['mo_scim_base_url'] ) && ! empty( $_POST['mo_scim_base_url'] ) ) {
				$baseUrl = $_POST['mo_scim_base_url'];
			}
			if ( isset( $_POST['mo_scim_api_token'] ) && ! empty( $_POST['mo_scim_api_token'] ) ) {
				$token = $_POST['mo_scim_api_token'];
			}

			$count_keys = count( $baseUrl );

			if ( $count_keys > 0 ) {
				$baseUrl = array_map( 'htmlspecialchars',$baseUrl );
				$token   = array_map( 'sanitize_text_field',$token );
				$index   = 0;
				while ( $index < $count_keys ) {
					if ( isset( $_POST[ 'mo_scim_cross_provisioning_' . $index ] ) && ! empty( $_POST[ 'mo_scim_cross_provisioning_' . $index ] ) ) {
						array_push( $tokens_to_display,$index );
					}
					$index ++;
				}
			}

			update_site_option( 'mo_scim_cross_provisioning',$tokens_to_display );
			$url_token = array_combine( $baseUrl,$token );

			$url_token = array_filter( $url_token );

			if ( ! empty( $url_token ) ) {
				update_site_option( 'mo_scim_cross_provisioning_url_token',$url_token );
			} else {
				$url_token = get_site_option( 'mo_scim_cross_provisioning_url_token' );
				if ( ! empty( $url_token ) ) {
					delete_site_option( 'mo_scim_cross_provisioning_url_token' );
				}
			}
		} elseif ( mo_check_option_admin_referer( 'scim_up_clear_attribute' ) ) {
			delete_site_option( 'mo_scim_test_config_attrs' );
		} else if (mo_check_option_admin_referer('mo_scim_advanced_reports')) {
			// Advance search option from the report tab
			$username = "";
			$ip = "";
			$status = "";
			$user_action = "";
			$from_date = "";
			$to_date = "";

			if ($_POST['username']) {
				$username = sanitize_text_field($_POST['username']);
			}
			if ($_POST['ip']) {
				$ip = sanitize_text_field($_POST['ip']);
			}
			if ($_POST['status']) {
				$status = sanitize_text_field($_POST['status']);
			}
			if ($_POST['user_action']) {
				$user_action = sanitize_text_field($_POST['user_action']);
			}
			if ($_POST['from_date']) {
				$from_date = sanitize_text_field($_POST['from_date']);
			}
			if ($_POST['to_date']) {
				$to_date = sanitize_text_field($_POST['to_date']);
			}

			update_site_option('mo_scim_advanced_search_username', $username);
			update_site_option('mo_scim_advanced_search_ip', $ip);
			update_site_option('mo_scim_advanced_search_status', $status);
			update_site_option('mo_scim_advanced_search_action', $user_action);
			update_site_option('mo_scim_advanced_search_from_date', $from_date);
			update_site_option('mo_scim_advanced_search_to_date', $to_date);
			update_site_option('mo_scim_advanced_reports', true);
	}
	else if( mo_check_option_admin_referer('mo_scim_clear_advance_search' ) ) {
		update_site_option('mo_scim_advanced_search_username', '');
		update_site_option('mo_scim_advanced_search_ip', '');
		update_site_option('mo_scim_advanced_search_status', 'default');
		update_site_option('mo_scim_advanced_search_action', 'User Login');
		update_site_option('mo_scim_advanced_search_from_date', '');
		update_site_option('mo_scim_advanced_search_to_date', '');
		update_site_option('mo_scim_advanced_reports', true);
	}
	
	elseif ( mo_check_option_admin_referer( 'mo_scim_hide_advanced_search' ) ) {
		update_site_option('mo_scim_advanced_reports', false);
	}

	elseif ( mo_check_option_admin_referer( 'mo_scim_manual_clear' ) ) {
		global $wpdb;
		$wpdb->query("DELETE FROM ".$wpdb->base_prefix.mo_scim_constants::USER_TRANSCATIONS_TABLE."");
	}

	update_site_option( 'show_attribute',false);
}

	function mo_check_option_admin_referer( $option_name ) {
		return ( isset( $_POST['option'] ) and $_POST['option'] == $option_name and check_admin_referer( $option_name ) );
	}
	function mo_scim_up_check_empty_or_null( $value ) {
		if ( ! isset( $value ) || empty( $value ) ) {
			return true;
		}

		return false;
	}
	function create_customer() {
		$userProv    = new scim_user_provisioner_add_on();
		$customer    = new CustomerUp();
		$customerKey = json_decode( $customer->create_customer(),true );
		if ( strcasecmp( $customerKey['status'],'CUSTOMER_USERNAME_ALREADY_EXISTS' ) == 0 ) {
			get_current_customer();
			delete_site_option( 'mo_scim_up_new_customer' );
		} elseif ( strcasecmp( $customerKey['status'],'SUCCESS' ) == 0 ) {
			update_site_option( 'mo_scim_up_admin_customer_key',$customerKey['id'] );
			update_site_option( 'mo_scim_up_admin_api_key',$customerKey['apiKey'] );
			update_site_option( 'mo_scim_up_customer_token',$customerKey['token'] );
			update_site_option( 'password','' );
			update_site_option( 'mo_scim_up_message','Registered successfully.' );
			delete_site_option( 'mo_scim_up_verify_customer' );
			delete_site_option( 'new_registration' );
			$userProv->mo_scim_up_show_success_message();
		}
	}

	function get_current_customer() {
		$userProv    = new scim_user_provisioner_add_on();
		$customer    = new CustomerUp();
		$content     = $customer->get_customer_key();
		$customerKey = json_decode( $content,true );
		if ( json_last_error() == JSON_ERROR_NONE ) {
			update_site_option( 'mo_scim_up_admin_customer_key',$customerKey['id'] );
			update_site_option( 'mo_scim_up_admin_api_key',$customerKey['apiKey'] );
			update_site_option( 'mo_scim_up_customer_token',$customerKey['token'] );
			update_site_option( 'mo_scim_up_admin_password','' );
			update_site_option( 'mo_scim_up_message','Your account has been retrieved successfully.' );
			delete_site_option( 'mo_scim_up_verify_customer' );
			$userProv->mo_scim_up_show_success_message();
		} else {
			update_site_option( 'mo_scim_up_message','You already have an account with miniOrange. Please enter a valid password.' );
			update_site_option( 'mo_scim_up_verify_customer','true' );
			$userProv->mo_scim_up_show_error_message();
		}
	}

	function mo_scim_up_is_curl_installed() {
		if ( in_array( 'curl',get_loaded_extensions() ) ) {
			return 1;
		} else {
			return 0;
		}
	}
