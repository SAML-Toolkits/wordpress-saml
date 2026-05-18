<?php

class mo_scim_handler{
	
	
	function create_db(){
		global $wpdb;
		$tableName = $wpdb->base_prefix.mo_scim_constants::USER_TRANSCATIONS_TABLE;
		if($wpdb->get_var("show tables like '$tableName'") != $tableName) 
		{
			$sql = "CREATE TABLE ".$tableName." (
			`id` bigint NOT NULL AUTO_INCREMENT, `ip_address` mediumtext NOT NULL ,  `username` mediumtext NOT NULL ,
			`type` mediumtext NOT NULL , `url` mediumtext NOT NULL , `status` mediumtext NOT NULL , `created_timestamp` int, UNIQUE KEY id (id) );";
			require_once(ABSPATH . 'wp-admin/includes/upgrade.php');
			dbDelta($sql);
		}
    }

    function add_transactions($ipAddress, $username, $type, $status){
		global $wpdb;
		if ($username == '') {
		    $username = "-";
        }
		$wpdb->insert(
			$wpdb->base_prefix.mo_scim_constants::USER_TRANSCATIONS_TABLE,
			array( 
				'ip_address' => $ipAddress, 
				'username' => $username,
				'type' => $type,
				'status' => $status,
				'created_timestamp' => current_time( 'timestamp' )
			)
		);
	}

    function get_all_transactions() {
        global $wpdb;
        $myrows = $wpdb->get_results("SELECT ip_address, username, type, status, created_timestamp FROM " . $wpdb->base_prefix . mo_scim_constants::USER_TRANSCATIONS_TABLE . " order by id desc limit 5000");
        return $myrows;
    }

    function get_all_transactions_using_advanced_search(){
		global $wpdb;
        $myrows = "";
        if (get_site_option('mo_scim_advanced_reports')) {
            $username = get_site_option('mo_scim_advanced_search_username');
            $ip = get_site_option('mo_scim_advanced_search_ip');
            $status = get_site_option('mo_scim_advanced_search_status');
            $user_action = get_site_option('mo_scim_advanced_search_action');
            $from_date = get_site_option('mo_scim_advanced_search_from_date');
            $to_date = get_site_option('mo_scim_advanced_search_to_date');

            $where_clause = " where ";
            $is_previous_added = false;
            if ($username) {
                $where_clause .= " username LIKE '".$username."%'";
                $is_previous_added = true;
            }
            if ($ip) {
                if ($is_previous_added) {
                    $where_clause .= " AND ip_address = '".$ip."'";
                }
                else {
                    $where_clause .= " ip_address = '".$ip."'";
                    $is_previous_added = true;
                }
            }
            if ($status && $status != "default") {
                if ($is_previous_added) {
                    if ($status == "failed") {
                        $where_clause .= " AND status != 'success'";
                    } else {
                        $where_clause .= " AND status = '" . $status . "'";
                    }
                }
                else {
                    if ($status == "failed") {
                        $where_clause .= " status != 'success'";
                    } else {
                        $where_clause .= " status = '" . $status . "'";
                    }
                    $is_previous_added = true;
                }
            }
            if ($user_action) {
                if ($is_previous_added) {
                    $where_clause .= " AND type = '".$user_action."'";
                }
                else {
                    $where_clause .= " type = '".$user_action."'";
                    $is_previous_added = true;
                }
            }
            $has_date_error = false;
            if ($from_date && $to_date && $from_date != $to_date) {
                $from_date = DateTime::createFromFormat('Y-m-d', $from_date);
                $to_date = DateTime::createFromFormat('Y-m-d', $to_date);
                if ($from_date->getTimestamp() > $to_date->getTimestamp()) {
                    update_site_option( 'mo_scim_message', 'Invalid selection date interval');
                    $has_date_error = true;
                } else {
                    $where_clause .= " AND created_timestamp >= " . $from_date->getTimestamp() . " AND created_timestamp <= " . $to_date->getTimestamp();
                }
            } else if ($from_date || $to_date) {
                $date = $from_date ? $from_date : $to_date;
                $date = DateTime::createFromFormat('Y-m-d', $date);
                $timestamp = $date->getTimestamp();
                $beginOfDay = strtotime("midnight", $timestamp);
                $endOfDay   = strtotime("tomorrow", $beginOfDay) - 1;
                $where_clause .= " AND created_timestamp >= " . $beginOfDay . " AND created_timestamp <= " . $endOfDay;
            }
            if ($has_date_error) {
                add_action( 'admin_notices', array( $this, 'error_message') );
                $this->error_message();
                $myrows = $wpdb->get_results("SELECT ip_address, username, type, status, created_timestamp FROM " . $wpdb->base_prefix . mo_scim_constants::USER_TRANSCATIONS_TABLE . " order by id desc limit 5000");
            }
            else {
                $myrows = $wpdb->get_results("SELECT ip_address, username, type, status, created_timestamp FROM " . $wpdb->base_prefix . mo_scim_constants::USER_TRANSCATIONS_TABLE . $where_clause);
            }
        }
        else {
            $myrows = $wpdb->get_results("SELECT ip_address, username, type, status, created_timestamp FROM " . $wpdb->base_prefix . mo_scim_constants::USER_TRANSCATIONS_TABLE . " order by id desc limit 5000");
        }
        return $myrows;
	}
}

?>