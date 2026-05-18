<?php

class ScimCore{

    public static function Search_filter_query( $url ) {
        $url_parts = parse_url( $url );
        $search_variable = '';
        $search_value    = '';
        $match_operation = '';
        parse_str( $url_parts['query'],$params );
        if ( array_key_exists( 'filter',$_GET ) ) {
            $filter_array = explode( ' ',$_GET['filter'] );
            try{
                if ( count( $filter_array ) < 3 ) {
                    throw new Exception( "Invalid Search query" );
                }
                $search_variable = $filter_array[0];
                $match_operation = $filter_array[1];
                $search_value    = str_replace( '\"','',$filter_array[2] );
            }catch ( Exception $e ){
                echo 'error:' . $e->getMessage();
            }

            return self::UserSchema( $search_variable,$match_operation,$search_value );
        } elseif ( array_key_exists( 'count',$params ) ) {
            $payload['schemas']      = array( 'urn:ietf:params:scim:api:messages:2.0:ListResponse' );
            $payload['totalResults'] = 0;
            $payload['startIndex']   = 1;
            $payload['itemsPerPage'] = 0;
            $count                   = $params['count'];
            $startindex              = array_key_exists( 'startIndex',$params )?$params['startIndex']:0;
            if ( $startindex > 0 ) {
                $payload['startIndex'] = (int) $startindex;
                $startindex            = $startindex - 1;
            }
            $payload['Resources'] = array();
            global $wpdb;
            $user_query = $wpdb->get_results( "SELECT ID FROM $wpdb->users ORDER BY ID LIMIT $startindex,$count" );
            $totalUsers = $wpdb->get_var( "SELECT COUNT(*) FROM $wpdb->users" );
            foreach ( $user_query as $userid ) {
                $UserID                 = (int) $userid->ID;
                $user                   = get_user_by( 'id',$UserID );
                $payload['Resources'][] = ( self::CreateUserSchema( $user ) );
            }
            if ( $count > 0 && $count < $totalUsers ) {
                $payload['itemsPerPage'] = $count;
            } elseif ( $totalUsers > 0 ) {
                $payload['itemsPerPage'] = (int) $totalUsers;
            }
            $payload['totalResults'] = (int) $totalUsers;

            //header("Content-Type: application/json", true, 200);
            return json_encode( $payload );
        } elseif ( array_key_exists( 'scimFilter',$_GET ) ) {
            return self::UserSchema( $_GET['scimFilter'],'eq',$_GET['scimFilter'] );
        }
        // TODO
        // Check for http status and return

    }

    static public function UserSchema( $search_variable,$match_operation,$search_value ) {
        switch ( $match_operation ) {
            case 'eq' :
                $user = get_user_by( 'login',$search_value );
                if ( ! $user ) {
                    if ( is_email( $search_value ) ) {
                        $user = get_user_by( 'email',$search_value );
                    } else {
                        if ( is_int( $search_value ) ) {
                            $user = get_user_by( 'ID',$search_value );
                        }
                    }
                }
                if ( $user ) {
                    return self::SendUserSchema( $user );
                }

                return self::SendEmptyResponse();
                break;
        }
    }

    public static function SendUserSchema( $user ) {
        $send_query = self::CreateUserSchema( $user );
        return self::SendUserDetails( $send_query );
    }

    static public function CreateUserSchema( WP_User $user ) {
        $login_value       = $user->user_email ?? $user->user_login;
        $custom_attributes = maybe_unserialize( get_site_option( 'mo_scim_custom_attrs_mapping' ) );
        $FirstName         = get_user_meta( $user->ID,'first_name',true ) ?? '';
        $FamilyName        = get_user_meta( $user->ID,'last_name',true ) ?? '';
        $title             = get_user_meta( $user->ID,'title',true ) ?? '';
        if ( get_user_meta( $user->ID,'mo_scim_user_status',true ) == 'inactive' ) {
            $deprovision_status = false;
        } else {
            $deprovision_status = true;
        }
        $schema        = self::getSchema( 'User' );
        $custom_schema = self::getSchema( 'CustomExtension' );

        $send_query_array         = array(
            'schemas'     => $schema,
            'id'          => strval($user->ID),
            'meta'        => array( 'resourceType' => 'User' ),
            'name'        => array(
                "formatted"  => $FamilyName . ' ' . $FirstName,
                'familyName' => $FamilyName,
                'givenName'  => $FirstName
            ),
            'title'       => $title,
            'displayName' => $user->display_name,
            'userName'    => $user->user_login,
            'active'      => $deprovision_status,
            'emails'      => array( ( array( 'primary' => true,'value' => $login_value ) ) )
            //primary should be a bool
        );
        $custom_attributes_Schema = array();
        if ( is_array( $custom_attributes ) ) {
            foreach ( $custom_attributes as $key => $value ) {
                $custom_attributes_Schema[ $key ] = get_user_meta( $user->ID,$key,true );
            }
        }
        $send_query_array[ $custom_schema ] = $custom_attributes_Schema;
        if ( ! ( $custom_attributes_Schema ) ) {
            $send_query_array['schemas'] = array( $schema,$custom_schema );
        }
        else{
            $send_query_array['schemas'] = array( $send_query_array['schemas']);
        }
        if ( function_exists( 'xprofile_get_field_data' ) ) {
            $custom_bp_attributes        = maybe_unserialize( get_site_option( 'mo_scim_custom_attrs_mapping_buddypress' ) );
            $custom_bp_attributes_Schema = array();
            if ( is_array( $custom_bp_attributes ) ) {
                foreach ( $custom_bp_attributes as $key => $value ) {
                    $custom_bp_attributes_Schema[ $key ] = xprofile_get_field_data( $key,$user->ID );
                }
            }
            $send_query_array[ $custom_schema ] += $custom_bp_attributes_Schema;
        }

        /**
         * Filter to change user schema for custom implementation.
         * $send_query_array = array consists of all current user details
         * $user = wp_user object of queried user
         */
        return apply_filters( 'mo_scim_user_details',$send_query_array,$user );
    }

    public static function getSchema( $schema ) {
        switch ( $schema ) {
            case 'User':
                return  "urn:ietf:params:scim:schemas:core:2.0:User" ;
                break;
            case 'CustomExtension':
                return 'urn:ietf:params:scim:schemas:extension:CustomExtensionName:2.0:User';
                break;
            case 'EnterpriseUser':
                /*To include address and zip code and other enterprise stuff*/
                return 'urn:ietf:params:scim:schemas:extension:enterprise:2.0:User';
                break;
        }
    }

    public static function SendUserDetails( $SendQuery,$count = 1,$itemPerPage = 20 ) {
        $correct_query = '{
                      "schemas":["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
                      "totalResults":' . $count . ',
                      "itemsPerPage":' . $itemPerPage . ',
                      "startIndex":1,
                      "Resources":[
                                   ' . json_encode( $SendQuery ) . '
                                  ]
                     }';

        return $correct_query;
    }

    public static function SendEmptyResponse() {
        $vaildate = '{
                 "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
                 "totalResults": 0,
                 "startIndex": 1,
                 "itemsPerPage": 0,
                 "Resources": []
            }';
        header( "Content-Type: application/json",true,200 );
        exit( $vaildate );
    }

    public static function ListAllResoures() {
        $payload['schemas']      = array( 'urn:ietf:params:scim:api:messages:2.0:ListResponse' );
        $payload['totalResults'] = 0;
        $payload['startIndex']   = 1;
        $payload['itemsPerPage'] = 0;
        global $wpdb;
        $totalUsers           = $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM $wpdb->users" ) );
        $count                = $totalUsers > 50 ? 50 : $totalUsers;
        $payload['Resources'] = array();
        $user_query           = $wpdb->get_results( $wpdb->prepare( "SELECT ID FROM $wpdb->users ORDER BY ID LIMIT 1,$count" ) );
        foreach ( $user_query as $userid ) {
            $UserID                 = (int) $userid->ID;
            $user                   = get_user_by( 'id',$UserID );
            $payload['Resources'][] = self::CreateUserSchema( $user );
        }
        if ( $count > 0 && $count < $totalUsers ) {
            $payload['itemsPerPage'] = $count;
        } elseif ( $totalUsers > 0 ) {
            $payload['itemsPerPage'] = (int) $totalUsers;
        }
        $payload['totalResults'] = (int) $totalUsers;

        return json_encode( $payload );
    }

    public static function PatchUser( $requestBody,$userID ) {

        $modify_username_status = false;
        $modified_username = '';
        foreach ( $requestBody as $key => $value ) {
            if ( in_array( $key,array( 'schemas','id','groups' ) ) ) {
                continue;
            } elseif ( $key == "Operations" && is_array( $value ) ) {
                foreach ( $value as $keyg => $val ) {
                    if ( $val['op'] === "Replace" || $val['op'] === "replace" ) {
                        if ( self::checkDeprovisionScimArray( $val ) )
                        	self::deprovisionUserBasedOnMode( get_user_by( 'ID', $userID ), $requestBody );
                        else
                        	update_user_meta( $userID,'mo_scim_user_status','active' );

                    } elseif ( $val['op'] === "Add" ) {
                        if ( $val['value'] == "userName" ) {
                            $user = get_user_by( 'login',$val['value'] );
                            if ( $user->ID != $userID ) {
                                $modify_username_status = true;
                                $modified_username      = $user->user_login;
                            }
                        }

                    }
                    self::handlePatchUpdateUser($val,$userID,$modify_username_status,$modified_username);
                }
                if($modify_username_status !== false) {
                    if( get_site_option('mo_scim_username_error') == false ) {         
                        if( get_site_option('mo_scim_transaction_log') === 'true' ){
                            mo_scim_update_success($userID, $requestBody);
                        }
                        exit( self::throwError( 400,"Could not modify userName. There is already an existing user " . $modified_username . " with the same name." ) );
                    }
                }
            }
        }

        /**
         *
         * Add custom logic to after user is updated by SCIM user plugin by patch request.
         *
         */

        do_action( 'mo_scim_updated_user_by_patch',$userID );
        if( get_site_option('mo_scim_transaction_log') === 'true' ){
            mo_scim_update_success($userID, $requestBody);
        }

        header( "Content-Type: application/json",true,200 );
        echo json_encode( self::CreateUserSchema( get_user_by( 'ID',$userID ) ) );
        exit;
    }

    public static function throwError( $statusCode,$description ) {
        do_action( 'mo_scim_custom_error' );
        header( "Content-Type: application/json",true,$statusCode );
        exit( json_encode( array(
            'schemas' => array( "urn:ietf:params:scim:api:messages:2.0:Error" ),
            'detail'  => $description,
            'status'  => $statusCode
        ) ) );
    }
        public static function checkDeprovisionScimArray( $array ) {
		$condition1 = isset($array['value']['active']) && $array['value']['active'] === false;
		$condition2 = isset($array['path'], $array['value']) && $array['path'] === 'active' && $array['value'] === 'False';

		return $condition2 || $condition1;
	}

    public static function handlePatchUpdateUser($val,$userID,&$modify_username_status,&$modified_username) {
        if(!isset($val['path']) || !isset($val['value'])){
            return;
        }
	    if ( $val['path'] == "userName" ) {
            $modify_username_status = true;
            $modified_username      = $val['value'];
	    }
	    if ( $val['path'] == 'active' ) {
		    update_user_meta( $userID,'mo_scim_user_status',$val['value'] );
		    if ( $val['value'] !== true || $val['value'] !== 'true' ) {
                      $json="";
			    self::deprovisionUserBasedOnMode( get_user_by( 'ID', $userID ), $json );
		    }
	    }
        if ( strpos( $val['path'],'urn:ietf:params:scim:schemas:extension:CustomExtensionName:2.0:User:' ) !== false ) {
            $attrs = str_replace( 'urn:ietf:params:scim:schemas:extension:CustomExtensionName:2.0:User:','',$val['path'] );
            if(strpos( $attrs, "bb_") !== false )
            {
                $newAttr = str_replace( 'urn:ietf:params:scim:schemas:extension:CustomExtensionName:2.0:User:','urn:ietf:params:scim:schemas:extension:CustomExtensionName:2.0:User.',$val['path'] );
                $customAttribute = [
                    "scim.".$newAttr => $val['value']
                ];
                mo_scim_up_map_custom_attributes_buddypress( $userID , $customAttribute );
            } else {
                update_user_meta( $userID,$attrs,$val['value'] );
            }
        }
        if ( $val['path'] == 'name.givenName' ) {
            update_user_meta( $userID,'first_name',$val['value'] );
        }
        if ( $val['path'] == 'name.familyName' ) {
            update_user_meta( $userID,'last_name',$val['value'] );
        }
        if ( $val['path'] == 'name.formatted' ) {
            update_user_meta( $userID,'formatted',$val['value'] );
        }
        if ( $val['path'] == 'emails[type eq "work"].value' ) {
            wp_update_user( array( 'ID' => $userID,'user_email' => $val['value'] ) );
        }
        if ( $val['path'] == 'displayName' ) {
            wp_update_user( array( 'ID' => $userID,'display_name' => $val['value'] ) );
        }
    }

    public static function deprovisionUserBasedOnMode( $user, $json ) {
        if( get_site_option('mo_scim_transaction_log') === 'true' ){
            mo_scim_delete_success($user->ID, $json);
        }
        if ( is_admin_user( $user->ID ) ) {
            $deprovision_for_admins = get_site_option( 'mo_scim_deprovision_for_admins' );
            if ( !empty( $deprovision_for_admins ) && $deprovision_for_admins != 'true' ) {
                self::deprovisionUserFromWp( $user,true );
            }
        }

        $user_deprovisioning_mode = get_site_option( 'mo_scim_user_deprovisioning_mode' );
        if ( $user_deprovisioning_mode == 'deactivate' ) {
            update_user_meta( $user->ID,'mo_scim_user_status','inactive' );
            self::deprovisionUserFromWp( $user,'false' );
        } else {
            self::deprovisionUserFromWp( $user,'false' );
        }
    }

    public static function deprovisionUserFromWp( $user,$active ) {
        $json = json_encode( self::CreateUserSchema( $user ) );

        do_action( 'mo_scim_before_deprovisioning_user',$user,$active );

        if ( get_site_option( 'mo_scim_user_deprovisioning_mode' ) !== 'deactivate' ) {
            if ( is_multisite() ) {
                require_once( ABSPATH . 'wp-admin/includes/ms.php' );
                wpmu_delete_user($user->ID);
            } else {
                if (file_exists(ABSPATH . 'wp-admin/includes/ms.php')) {
                    require_once(ABSPATH . 'wp-admin/includes/ms.php');
                }
                require_once( ABSPATH . 'wp-admin/includes/user.php' );
                wp_delete_user($user->ID);
            }
        }
        $sessions = WP_Session_Tokens::get_instance( $user->ID );
        $sessions->destroy_all();
        header( "HTTP/1.1 200 OK" );
        header( 'Content-Type: application/json;charset=utf-8' );
        echo $json;
        exit;
    }

}