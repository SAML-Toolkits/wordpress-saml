<?php
	/**
	 * Plugin Name: miniOrange SCIM User provisioning
	 * Plugin URI: http://miniorange.com
	 * Description: This plugin Enables user provisioning through a Identity provider to WordPress with SCIM 2.0 standard.
	 * Version: 20.0.4
	 * Author: miniOrange
	 * Author URI: http://miniorange.com
	 * License: GPL2
	 */

	require_once( 'mo-scim-user-provisioner-save.php' );
	require_once( 'mo-scim-user-provisioner-menu-settings.php' );
	if ( ! class_exists( "AESEncryptionInPR" ) ) {
		require_once dirname( __FILE__ ) . '/includes/lib/encryption.php';
	}
	define( 'MO_SCIM_DIR',dirname( __FILE__ ) . '/' );
	define('MO_SCIM_DB_VERSION', '58975');

	class scim_user_provisioner_add_on{

		function __construct() {
			// register_activation_hook(__FILE__,array($this,'check_some_other_plugin'));
			update_site_option( 'mo_scim_up_host_name','https://login.xecurify.com' );
			$this->init_hook();

		}
		function init_hook(){
			if ( is_multisite() ) {
				add_action( 'network_admin_menu',array( $this,'miniorange_menu' ),11 );
				add_filter( 'wpmu_users_columns',array( $this,'mo_scim_up_custom_attr_column' ) );
				remove_action( 'network_admin_notices',array( $this,'mo_scim_up_success_message' ) );
				remove_action( 'network_admin_notices',array( $this,'mo_scim_up_error_message' ) );
			} else {
				add_action( 'admin_menu',array( $this,'miniorange_menu' ),11 );
				add_filter( 'manage_users_columns',array( $this,'mo_scim_up_custom_attr_column' ) );
				remove_action( 'admin_notices',array( $this,'mo_scim_up_success_message' ) );
				remove_action( 'admin_notices',array( $this,'mo_scim_up_error_message' ) );
			}
			add_action( 'admin_init','miniorange_save_setting_user_provisioning',1 );
			add_action( 'wp_ajax_fetch_transaction_payload', array( $this, 'fetch_transaction_payload' ));
			add_action( 'init','mo_scim_user_provisioning_validate' );
			register_deactivation_hook( __FILE__,array( $this,'mo_scim_up_deactivate' ) );
			add_action( 'admin_enqueue_scripts',array( $this,'plugin_settings_script' ) );
			add_action( 'admin_enqueue_scripts',array( $this,'plugin_settings_style' ) );
			
			add_action( 'wp_login',array( $this,'mo_scim_check_active_user' ),10,2 );
			add_action( 'manage_users_custom_column',array( $this,'mo_scim_up_attr_column_content' ),10,4 );
			register_activation_hook( __FILE__, array($this,'mo_scim_activate'));
			add_action( 'admin_init', array( $this, 'mo_scim_add_payload' ) );
		}

		function mo_scim_add_payload() {
			global $wpdb;
			
			if( !get_site_option( 'mo_scim_db_version' )  || get_site_option( 'mo_scim_db_version' ) < MO_SCIM_DB_VERSION){
				$tableName = $wpdb->prefix . 'scim_transactions';
				$column_exists = $wpdb->get_var("SHOW COLUMNS FROM `$tableName` LIKE 'payload'");
				
				if ( !$column_exists ) {
					$wpdb->query("ALTER TABLE `$tableName` ADD `payload` LONGTEXT NOT NULL");
				}
				update_site_option( 'mo_scim_db_version', MO_SCIM_DB_VERSION );
			}
			
		}
		
		function miniorange_menu() {
			add_menu_page( 'SCIM User Provisioner','SCIM User Provisioner','administrator','user_provisioning','user_provisioning',plugin_dir_url( __FILE__ ) . 'images/miniorange.png' );
		}

		function mo_scim_check_active_user( $username,$user ) {
			$deprovision_status = get_user_meta( $user->ID,'mo_scim_user_status',true );
			if ( $deprovision_status == 'inactive' ) {
				wp_clear_auth_cookie();
				wp_die( 'We could not sign you in. The user has been deactivated','Error: Not Authorized' );
				exit();
			}
		}

		function mo_scim_up_deactivate() {
			//do_action('Update_license_key');
			do_action( 'mo_scim_up_flush_cache' );
			delete_site_option( 'mo_scim_up_admin_email' );
			delete_site_option( 'mo_scim_up_admin_customer_key' );
			delete_site_option( 'mo_scim_up_host_name' );
			delete_site_option( 'mo_scim_up_admin_phone' );
			delete_site_option( 'mo_scim_up_admin_password' );
			delete_site_option( 'mo_scim_up_admin_customer_key' );
			delete_site_option( 'mo_scim_up_admin_api_key' );
			delete_site_option( 'mo_scim_up_customer_token' );
			delete_site_option( 'mo_scim_up_message' );
			delete_site_option( 'mo_scim_up_vl_check_s' );
			delete_site_option( 'mo_scim_up_lk' );
			
			//delete audit wp_options
			delete_site_option('mo_scim_transactionId');
			delete_site_option('mo_scim_registration_status');
		}

		function mo_scim_activate() {
			$mo_scim_config = new mo_scim_handler();
			$mo_scim_config->create_db();
			update_site_option( 'mo_scim_enable_brute_force', true);
			update_site_option( 'mo_scim_show_remaining_attempts', true);
		}

		function plugin_settings_style( $page ) {
			if ( $page != 'toplevel_page_user_provisioning' ) {
				return;
			}
			wp_enqueue_style( 'mo_scim_up_admin_settings_phone_style',plugins_url( 'includes/css/phone.min.css',__FILE__ ) );
			wp_enqueue_style( 'mo_scim_up_admin_setting_style',plugins_url( 'includes/css/style_settings.css',__FILE__ ) );
		}

		function plugin_settings_script( $page ) {
			if ( $page != 'toplevel_page_user_provisioning' ) {
				return;
			}
			wp_enqueue_script( 'jquery' );
			wp_enqueue_script( 'mo_scim_up_admin_settings_script',plugins_url( 'includes/js/settings.js',__FILE__ ) );
			wp_enqueue_script( 'mo_scim_up_admin_settings_phone_script',plugins_url( 'includes/js/phone.min.js',__FILE__ ) );
			wp_localize_script('mo_scim_up_admin_settings_script', 'ajax_scim', array(
				'url' => admin_url('/admin-ajax.php'),
				'nonce' => wp_create_nonce('ajax-nonce'))
			);
		}

		function mo_scim_up_show_success_message() {
			if ( is_multisite() ) {
				remove_action( 'network_admin_notices',array( $this,'mo_scim_up_error_message' ) );
				add_action( 'network_admin_notices',array( $this,'mo_scim_up_success_message' ) );
			} else {
				remove_action( 'admin_notices',array( $this,'mo_scim_up_error_message' ) );
				add_action( 'admin_notices',array( $this,'mo_scim_up_success_message' ) );
			}
		}

		function mo_scim_up_show_error_message() {
			if ( is_multisite() ) {
				remove_action( 'network_admin_notices',array( $this,'mo_scim_up_success_message' ) );
				add_action( 'network_admin_notices',array( $this,'mo_scim_up_error_message' ) );
			} else {
				remove_action( 'admin_notices',array( $this,'mo_scim_up_success_message' ) );
				add_action( 'admin_notices',array( $this,'mo_scim_up_error_message' ) );
			}
		}

		function mo_scim_up_success_message() {
			$class   = "updated";
			$message = get_site_option( 'mo_scim_up_message' );
			echo "<div class='" . $class . "'> <p>" . $message . "</p></div>";
		}

		function mo_scim_up_error_message() {
			$class   = "error";
			$message = get_site_option( 'mo_scim_up_message' );
			echo "<div class='" . $class . "'><p>" . $message . "</p></div>";
		}

		function mo_scim_up_custom_attr_column( $columns ) {
			$custom_attributes = maybe_unserialize( get_site_option( 'mo_scim_custom_attrs_mapping' ) );
			$attr_in_user_menu = get_site_option( 'scim_show_user_attribute' );
			$i                 = 0;
			if ( is_array( $custom_attributes ) ) {
				foreach ( $custom_attributes as $key => $value ) {
					if ( ! empty( $key ) ) {
						if ( in_array( $i,$attr_in_user_menu ) ) {
							$columns[ $key ] = $key;
						}
					}
					$i ++;
				}
			}
			if ( get_site_option( 'show_user_status' ) == 1 ) {
				$columns['mo_scim_user_status'] = 'user_status';
			}
			return $columns;
		}

		function mo_scim_up_attr_column_content( $output,$column_name,$user_id ) {
			$custom_attributes = get_site_option( 'mo_scim_custom_attrs_mapping' );
			if ( get_site_option( 'show_user_status' ) == 1 ) {
				$custom_attributes['mo_scim_user_status'] = 'user_status';
			}
			if ( is_array( $custom_attributes ) ) {
				foreach ( $custom_attributes as $key => $value ) {
					if ( $key === $column_name ) {
						$content = get_user_meta( $user_id,$column_name,false );
						if ( ! empty( $content ) ) {
							if ( ! is_array( $content[0] ) ) {
								return $content[0];
							} else {
								$result = '';
								foreach ( $content[0] as $attr_value ) {
									$result = $result . $attr_value;
									if ( next( $content[0] ) ) {
										$result = $result . ' | ';
									}
								}

								return $result;
							}
						}
					}
				}
			}
			return $output;
		}

		public function user_provisioning_get_current_page_url() {
			$http_host = $_SERVER['HTTP_HOST'];
			if ( substr( $http_host,- 1 ) == '/' ) {
				$http_host = substr( $http_host,0,- 1 );
			}
			$request_uri = $_SERVER['REQUEST_URI'];
			if ( substr( $request_uri,0,1 ) == '/' ) {
				$request_uri = substr( $request_uri,1 );
			}

			$is_https    = ( isset( $_SERVER['HTTPS'] ) && strcasecmp( $_SERVER['HTTPS'],'on' ) == 0 );
			$relay_state = 'http' . ( $is_https ? 's' : '' ) . '://' . $http_host . '/' . $request_uri;

			return $relay_state;
		}

		public function fetch_transaction_payload() {
	
			if (!isset($_POST['transaction_id'])) {
				wp_send_json_error(array('message' => 'Transaction ID is required.'));
			}
			$transaction_id = sanitize_text_field($_POST['transaction_id']);

			global $wpdb;
			$table_name = $wpdb->prefix . 'scim_transactions';
			$transaction = $wpdb->get_row(
				$wpdb->prepare("SELECT payload FROM $table_name WHERE id = %d", $transaction_id)
			);

			if ($transaction) {
				wp_send_json_success($transaction->payload);
			} else {
				wp_send_json_error(array('message' => 'Transaction not found.'));
			}
		}
	}

	add_action( 'mo_scim_up_flush_cache','mo_scim_up_flush_cache',10,3 );
	function mo_scim_up_flush_cache() {
		if ( mo_scim_up_is_customer_registered() && get_site_option( 'mo_scim_up_lk' ) ) {
			$customer = new CustomerUp();
			mo_scim_up_update_status();
		}
	}

	function mo_scim_up_is_customer_registered() {
		if ( class_exists( "Mo_Ldap_Local_Util" ) ) {
			$ldap = new Mo_Ldap_Local_Util();
		}

		if ( function_exists( "mo_saml_is_customer_registered_saml" ) && mo_saml_is_customer_registered_saml() || function_exists( "mo_oauth_is_customer_registered" ) && mo_oauth_is_customer_registered() || isset( $ldap ) && method_exists( $ldap,"is_customer_registered" ) && $ldap->is_customer_registered() ) {
			return 1;
		}
		$email       = get_site_option( 'mo_scim_up_admin_email' );
		$customerKey = get_site_option( 'mo_scim_up_admin_customer_key' );
		if ( ! $email || ! $customerKey || ! is_numeric( trim( $customerKey ) ) ) {
			return 0;
		} else {
			return 1;
		}
	}

	new scim_user_provisioner_add_on;
