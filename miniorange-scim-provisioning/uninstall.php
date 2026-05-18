<?php

	if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) ) {
		exit();
	}

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
	delete_site_option('mo_scim_custom_attrs_mapping_buddypress');
	delete_site_option('mo_scim_custom_attrs_mapping');