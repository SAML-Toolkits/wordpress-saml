<?php
include_once('mo_scim_atr-mapping.php');
include_once('mo_scim_atr-mapping_buddypress.php');
include_once('mo-scim-user-provisioner-audit.php');
include_once('mo-scim-user-provisioner-audit-class.php');

if ( ! class_exists( "AESEncryptionInPR" ) ) {
	require_once dirname( __FILE__ ) . '/includes/lib/encryption.php';
}
if( ! class_exists('ScimCore')){
    require_once dirname(__FILE__).'/includes/lib/ScimCore.php';
}

if( ! class_exists('mo_scim_constants')){
    require_once dirname(__FILE__).'/includes/lib/Constants.php';
}

function user_provisioning() {
    
	$currenttab = "";
	if ( array_key_exists( 'tab', $_GET ) ) {
		$currenttab = $_GET['tab'];
	} else if ( mo_scim_up_is_customer_registered() && mo_scim_up_is_customer_license_key_verified() )
    {
        $currenttab = 'sp_config';
    }
    else{
        $currenttab = 'login';
    }

	?>
    <div id="mo_scim_up_settings">
        <div class="miniorange_container">
            <table style="width:100%;">
                <tr>
                    <h2 class="nav-tab-wrapper">
						<?php if ( ! mo_scim_up_is_customer_registered() || ! mo_scim_up_is_customer_license_key_verified() ) { ?>
                            <a class="nav-tab <?php echo $currenttab == 'login' ? 'nav-tab-active' : ''; ?>"
                               href="<?php echo add_query_arg( array( 'tab' => 'login' ), htmlentities( $_SERVER['REQUEST_URI'] ) ); ?>">Account
                                Setup</a>
						<?php } ?> 
                        <a class="nav-tab <?php if ( $currenttab == 'sp_config' ) {
							echo 'nav-tab-active';
						} ?>"
                           href="admin.php?page=user_provisioning&tab=sp_config">SCIM Configuration</a>

                        <a class="nav-tab <?php if ( $currenttab == 'attribute_mapping' ) {
                            echo 'nav-tab-active';
                        } ?>"
                           href="admin.php?page=user_provisioning&tab=attribute_mapping">Attribute-Mapping</a>

                        <a class="nav-tab <?php if ( $currenttab == 'scim-audit' ) {
                            echo 'nav-tab-active';
                        } ?>"
                           href="admin.php?page=user_provisioning&tab=scim-audit">SCIM Audit</a>
                        
                        <?php if ( is_multisite() ) : ?>                        
                        <a class="nav-tab <?php if ( $currenttab == 'user-management' ) {
                            echo 'nav-tab-active';
                        } ?>"
                           href="admin.php?page=user_provisioning&tab=user-management">User Management</a>
                        <?php endif; ?>
                    </h2>

                   <td style="vertical-align:top;width:65%;">
						<?php
						if ( $currenttab == 'login' ) {

							if ( get_site_option( 'mo_scim_up_verify_customer' ) == 'true' ) {
								mo_scim_up_show_verify_password_page();
							} else if ( trim( get_site_option( 'mo_scim_up_admin_email' ) ) != '' && trim( get_site_option( 'mo_scim_up_admin_api_key' ) ) == '' && get_site_option( 'new_registration' ) != 'true' ) {
								mo_scim_up_show_verify_password_page();
							} else if ( ! mo_scim_up_is_customer_registered() ) {
								delete_site_option( 'password_mismatch' );
                                mo_scim_up_show_verify_password_page();
								// account_login();
							} else if ( ! mo_scim_up_is_customer_license_key_verified() ) {
								mo_scim_up_show_verify_license_page();
							} else {
								scim_user_provisioning_configuration();
								$currenttab = '';
							}
						} elseif ( $currenttab == 'sp_config' ) {
							scim_user_provisioning_configuration();
						} elseif ( $currenttab == 'scim-audit' ) {
                            scim_user_provisioning_troubleshooting();
                        }
						elseif ($currenttab=='attribute_mapping'){
                        //show_attribute_custom();
						show_attribute_mapping();
                        if ( function_exists('bp_is_active') ) {
                            mo_scim_display_attrs_list_buddypress();
                            }
                        }
                        elseif ( is_multisite() && $currenttab == 'user-management' ) {
                            scim_user_management();
                        }

						?>
                    </td>
                    <td style="vertical-align:top;padding-left:1%;">
                        <?php if($currenttab=='attribute_mapping')
                            {echo mo_scim_display_attrs_list();}
                        else
                        {echo mo_support_user_provisioning();
                            mo_scim_payload_view();
                        
                        }
                        ?>
                    </td>
                </tr>
            </table>
        </div>

		<?php

		echo '
    <form style="display:none;" id="loginform" action="' . get_site_option( 'mo_scim_up_host_name' ) . '/moas/login"
		target="_blank" method="post">
		<input type="email" name="username" value="' . get_site_option( 'mo_scim_up_admin_email' ) . '" />
		<input type="text" name="redirectUrl" value="' . get_site_option( 'mo_scim_up_host_name' ) . '/moas/viewlicensekeys" />
		<input type="text" name="requestOrigin" value="wp_scim_user_provisioning_plan"  />
		</form>
		';
		}

function mo_scim_up_show_verify_license_page() {

			echo '<div class="mo_scim_up_table_layout" style="padding-bottom:50px;!important">';


			echo '<h3>Verify License  [ <span style="font-size:13px;font-style:normal;"><a href="https://portal.miniorange.com/viewlicense" target="_blank" style="cursor:pointer;" >Click here to view your license key</a></span> ]</h3><hr>';


			echo '<form name="f" method="post" action="">
                        <input type="hidden" name="option" value="mo_scim_up_verify_license" />

                            <p><b><font color="#FF0000">*</font>Enter your license key to activate the plugin:</b>
                            <input class="mo_scim_up_table_textbox" required type="text" style="margin-left:40px;width:300px;"
                                name="mo_scim_up_licence_key" placeholder="Enter your license key to activate the plugin" ';
			echo '/>
                            </p>
                            <p><b><font color="#FF0000">*</font>Please check this to confirm that you have read it: </b>&nbsp;&nbsp;<input required type="checkbox" name="license_conditions" ';
			echo '/></p>
                            </p>

                            <ol>
                            <li>License key you have entered here is associated with this site instance. In future, if you are re-installing the plugin or your site for any reason. You should deactivate and then delete the plugin from WordPress console and should not manually delete the plugin folder. So that you can resuse the same license key.</li><br>
                            <li><b>This is not a developer\'s license.</b> Making any kind of change to the plugin\'s code will delete all your configuration and make the plugin unusable.</li>
                            <br>
                                <input type="submit" name="submit" value="Activate License" class="button button-primary button-large" ';

			echo '/>

                    </form>';


			echo '</div>
        <form name="f" method="post" action="" id="mo_scim_up_check_license">
            <input type="hidden" name="option" value="mo_scim_up_check_license"/>
        </form>';
		}

function mo_scim_up_show_verify_password_page() {
		?>
        <!--Verify password with miniOrange-->
        <form name="f" method="post" action="">
            <input type="hidden" name="option" value="mo_scim_up_verify_customer_value"/>
            <div class="mo_scim_up_table_layout" style="padding-bottom:50px;!important">
                <div id="toggle1" class="panel_toggle">
                    <h3>Login with miniOrange</h3>
                </div>
                <a href="https://login.xecurify.com/moas/idp/resetpassword" target="_blank">Click here if you forgot your password?</a></b>
                </p>

                <div id="panel1">

                    <table class="mo_scim_up_settings_table">
                        <tr>
                            <td><b><font color="#FF0000">*</font>Email:</b></td>
                            <td><input class="mo_scim_up_table_textbox" type="email" name="email"
                                       required placeholder="person@example.com"
                                       value="<?php echo get_site_option( 'mo_scim_up_admin_email' ); ?>"/></td>
                        </tr>
                        <tr>
                        <td><b><font color="#FF0000">*</font>Password:</b></td>
                        <td><input class="mo_scim_up_table_textbox" required type="password"
                                   name="password" placeholder="Choose your password"/></td>
                        </tr>
                        <tr>
                            <td>&nbsp;</td>
                            <td><input type="submit" name="submit"
                                       class="button button-primary button-large"/>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
        </td>


        </tr>
        </table>
    </div>
    </div>
       </form>

	<?php
}

function scim_user_provisioning_configuration() {
	global $wpdb;

	?>
    <div class="mo_table_layout">
		<?php
		if ( ! mo_scim_up_is_customer_license_key_verified() ) {
			?>

            <div style="display:block;color:red;background-color:rgba(251, 232, 0, 0.15);padding:5px;border:solid 1px rgba(255, 0, 9, 0.36);">
                Please <a
                        href="<?php echo add_query_arg( array( 'tab' => 'login' ), htmlentities( $_SERVER['REQUEST_URI'] ) ); ?>">Login with miniOrange</a> to configure the miniOrange SCIM User Provisioner Plugin.
            </div>
			<?php
		}
        else
        {
            $scim_idp_name = !empty(get_site_option('mo_scim_idp_name')) ? get_site_option('mo_scim_idp_name') : 'okta';
		echo '<div class="mo_scim_up_table_layout" style="padding-bottom:50px;!important">
                <div style="display:block;margin-top:10px;background-color:rgba(255, 255, 255, 255);padding:5px;border:solid 1px rgba(255, 255, 255, 255);">
                <h2>SCIM Configuration</h2><hr>
                
                <form id="mo_scim_idp_name" name="mo_scim_idp_name" method="post" action="">
                <input type="hidden" name="option" value="mo_scim_idp_name">' ;
                wp_nonce_field('mo_scim_idp_name');
                echo'
                <table width="60%" style="padding: 10px;">
                <tr><td style="30%"><b>Select your Identity provider:</b></td>';
                //<td><select name="msup_scim_idp_name" id ="msup_scim_idp_name" onchange="myFunction()" style="width: 100%">
                echo '<td><select name="mo_scim_idp_name" id ="mo_scim_idp_name_dropdown" onChange= "document.getElementById(\'mo_scim_idp_name\').submit()" style="width: 100%">
                <option value="azuread"';
           if($scim_idp_name == 'azuread')
                    {echo ' selected ';}
           echo '>AzureAD</option>
           <option value="centrify"';
           if($scim_idp_name == 'centrify')
                    {echo ' selected ';}
           echo'>Centrify</option>
           <option value="google-apps"';
           if($scim_idp_name == 'google-apps')
                    {echo ' selected ';}
           echo '>GoogleApps</option>     
           <option value="okta"';
                if($scim_idp_name == 'okta')
                    {echo ' selected ';}
           echo '>Okta</option>
                   <option value="onelogin"';
           if($scim_idp_name == 'onelogin')
                    {echo ' selected ';}
           echo'>OneLogin</option>
           <option value="pingone"';
           if($scim_idp_name == 'pingone')
                    {echo ' selected ';}
           echo '>PingOne</option>
                   <option value="other"';
           if($scim_idp_name == 'other')
                    {echo ' selected ';}
           echo '>Other</option>';
        if($scim_idp_name=='other')
            {$scim_idp_name='onelogin';}
        echo '>Other</option>
</select></td> <td style="padding-left:5%"> <a class="button button-primary" id ="link_to_guide" style="margin-left :5%,margin-top:5% " 
    cursor: pointer; " href="https://plugins.miniorange.com/wordpress-scim-user-provisioning-with-'.$scim_idp_name.'" target="_blank">Click here for guide</a> </td>
                </tr>
                <tr><td><br/></td></tr>
                <tr><td></td><td colspan="2" >';
                //<input type="submit" value="Save" class="button button-primary button-large">
echo '                
</td></tr>
</table><br/><br/>
<b>Select your Identity Provider from the list below, and you can find the link to the guide for setting up SCIM Provisioning below.</b>
<br/><br/>
</form>';

          echo '
          <div id="mo_saml_idps_grid_div" style="position: relative">';

                    echo '
                        <ul>
                        
                        <li><a style="cursor: pointer" target="_blank" href="https://plugins.miniorange.com/wordpress-scim-user-provisioning-with-azuread"><img src="'.plugins_url( 'images/idp-guides-logos/azure-ad.png', __FILE__ ).'"/><br><h4>AzureAD</h4></a></li>
                        <li><a style="cursor: pointer" target="_blank" href="https://plugins.miniorange.com/wordpress-scim-user-provisioning-with-centrify"><img src="'.plugins_url( 'images/idp-guides-logos/centrify.png', __FILE__ ).'" /><br><h4>Centrify</h4></a></li>
                        <li><a style="cursor: pointer" target="_blank" href="https://plugins.miniorange.com/wordpress-scim-user-provisioning-with-google-apps"><img src="'.plugins_url( 'images/idp-guides-logos/google-apps.png', __FILE__ ).'" /><br><h4>GoogleApps</h4></a></li>
                        <li><a style="cursor: pointer" target="_blank" href="https://plugins.miniorange.com/wordpress-scim-user-provisioning-with-okta"><img src="'.plugins_url( 'images/idp-guides-logos/okta.png', __FILE__ ).'"/><br><h4>Okta</h4></a></li>
                        <li><a style="cursor: pointer" target="_blank" href="https://plugins.miniorange.com/wordpress-scim-user-provisioning-with-onelogin"><img src="'.plugins_url( 'images/idp-guides-logos/onelogin.png', __FILE__ ).'" /><br><h4>OneLogin</h4></a></li>
                        <li><a style="cursor: pointer" target="_blank" href="https://plugins.miniorange.com/wordpress-scim-user-provisioning-with-pingone"><img src="'.plugins_url( 'images/idp-guides-logos/pingone.png', __FILE__ ).'" /><br><h4>PingOne</h4></a></li>
                        </ul>
                        ';
                        
                echo '</div>';
                echo '
                </br>
                <form name="f" style="margin-left:6px;" method="post" action="" >
                    <input type="hidden" name="option" value="generate_new_token_option" />
                    <h3>SCIM API Credentials: </h3>
                    ';
                    //-----------------------------------------------------
                 echo ' <table border="1" style="background-color:#FFFFFF; border:1px solid #CCCCCC; padding:0px 0px 0px 10px; margin:2px; border-collapse: collapse; width:98%">
                    <tr>
                        <td style="width:40%; padding: 15px;"><b>SCIM Base URL</b></td>';
                         if(mo_scim_up_is_customer_registered()){
                            echo '<td style="width:60%; padding: 15px;">'. site_url() . '/scim</td>';  //???
                         }else{
                            echo '<td style="width:60%; padding: 15px;">https://login.xecurify.com/moas</td>';  //????
                         }
                    echo '</tr>';
                    echo '<tr>
                        <td style="width:40%; padding: 15px;"><b>SCIM Bearer Token</b> <span style="padding-left:16px;">
                        <input type="submit" class="button" value="Generate New token"></span></td></form>';
                         if(mo_scim_up_is_customer_registered()){
                            {
                                $hideToken = false;

                                $bearer_token = '';
                                if(get_site_option('mo_scim_up_bearer_token') == "")
                                {
                                    $bearer_token=create_bearer_token();
                                }

                                else
                                {
//                                    $get_bearer = get_site_option('mo_scim_up_bearer_token');
//                                    $bearer_token = convert_uudecode($get_bearer);

                                      if($bearer_token === ''){
                                          $bearer_token = '•••••••••••••••••••••••••••••••••';
                                          $hideToken = true;
                                      }
                                      else{
                                          $bearer_token = convert_uudecode($bearer_token);
                                      }
                                }

                                echo '<td style="width:60%; padding: 15px;" id = "copyTokenRow" value = "'.$bearer_token.'">'. $bearer_token . '';

                                if($hideToken == false){
                                    echo '      <button type="button" onclick="copyToken()" id = "copyTokenButton" value = "'.$bearer_token.'"><img style = "" src="'.plugins_url( 'images/idp-guides-logos/copy-icon1.png', __FILE__ ).'" /></button></td>';
                                }
                                else{
                                    echo '</td>';
                                }
                            }
                         }else
                         {echo '<td style="width:60%; padding: 15px;">https://login.xecurify.com/moas</td>';}  //????
                    echo '</tr></table>';
        echo '
            <script>
            function copyToken() {
              var copyText = document.getElementById("copyTokenButton").value;
              navigator.clipboard.writeText(copyText);
            }
            </script>
            ';
		echo '
         <br/>
        <b>Note : To create new token click on Generate New Token Button.</b>
        </div>
        
        </div></div>
        ';

        echo '<div class="mo_scim_up_table_layout" style="padding-bottom:50px;!important">
                <div style="display:block;margin-top:10px;background-color:rgba(255, 255, 255, 255);padding:5px;border:solid 1px rgba(255, 255, 255, 255);">
                <h2>SCIM Operations</h2><hr>
                <form name="f" style="margin-left:6px;" method="post" action="" id="blockedpagesform">
                    <input type="hidden" name="option" value="" />';
                    //-----------------------------------------------------
                echo ' <table border="1" style="background-color:#FFFFFF; border:1px solid #CCCCCC; padding:0px 0px 0px 10px; margin:2px; border-collapse: collapse; width:98%">
                    <form method="post" action="">   
                    While provisioning, if you attempt to update the username, the plugin will return an error message on the IDP side, and the username will not be updated. This toggle allows you to skip the username update.</br>
                    <b>Note: </b>A wordpress username is not directly editable once an account is created.</ol>
                    <input type="hidden" name="option" value="mo_scim_username_error" />
                    <ol ><label class="switch"><input type="checkbox" id="scim_test" name="mo_scim_username_error" value = "true"';
                    checked( get_site_option( 'mo_scim_username_error' ) == true );

                echo' ><span class="slider round" ></span></label> <b style="left:-25px;">Skip userName update for WordPress Users</b></ol>
                 <tr><b>Create:</b>
                    <ol>It will create user using First Name, Last Name, Email and Username.<br/>
                    <b>Note: </b>If Username field is blank, it will copy email as a username, as WordPress does not accept blank Username.</ol>
                    <input type="hidden" name="option" value="mo_scim_deprovision_user_option">
                    <b>De-provisioning:</b><br/><br/>
                    Enable the following option to allow de-provisioning of admin users:<br/>
                    <b>Note: </b>This is disabled for multisite environment.</ol>';

                    if (is_multisite()){
                    echo '
                    <ol><label class="switch"><input type="checkbox" name="mo_scim_deprovision_for_admins" disabled value="true"';
                    }

                    else{
                        echo '<ol><label class="switch"><input type="checkbox" name="mo_scim_deprovision_for_admins" value="true"';
                    }

                 checked(get_site_option('mo_scim_deprovision_for_admins') == 'true');
                 echo '><span class="slider round"></span></label> <b>Enable De-Provisioning for Administrators</b></ol>
                    
                    By default, De-provisioning will delete the users from the WordPress site.<br/>
                    Instead of this, you can enable the following option to deactivate the deprovisioned users. A deactivated user will not be able to log into the site.
                    <br/>
                    
                    <ol><label class="switch"><input type="checkbox" name="mo_scim_disable_deprovisioned_users" value="true"';
                 checked(get_site_option('mo_scim_user_deprovisioning_mode') == 'deactivate');
                 echo '><span class="slider round"></span></label> <b>Deactivate de-provisioned users instead of deleting them.</b></ol>
                    ';

                 echo '<span style="padding-top: 10px; text-align: center; display: block"><input type="submit" class="button button-primary button-large" value="Save"></span>';
                    
                    //----------------------------
                echo '
                    </tr>
                    </table>';
        echo '</div></div></form>';
        //--------------------------------------------------------------
        echo '<div class="mo_scim_up_table_layout" style="padding-bottom:50px;!important">
                <div style="display:block;margin-top:10px;background-color:rgba(255, 255, 255, 255);padding:5px;border:solid 1px rgba(255, 255, 255, 255);">
                <h3>Instructions:</h3><hr>
                <form name="f" style="margin-left:6px;" method="post" action="" id="blockedpagesform">
                    <input type="hidden" name="option" value="" />';
                    //-----------------------------------------------------
                 echo ' <table border="1" style="background-color:#FFFFFF; border:1px solid #CCCCCC; padding:0px 0px 0px 10px; margin:2px; border-collapse: collapse; width:98%">
                 <ol><li>Enter the above SCIM Base URL on your IDP. </li><li>Enter the above SCIM Bearer Token under your IDP settings.</li><li>Once done with above configuration, you will be able perform add, update and delete operations on IDP under User Provisioning.</li>
                 </ol>';
                    //----------------------------
                echo '</table>';
        echo '</div></div></div></form>';

		}
    }

function scim_user_provisioning_troubleshooting() {
        
    global $wpdb;

    ?>
    <div class="mo_table_layout">
        <?php

        if ( ! mo_scim_up_is_customer_license_key_verified() ) {
            ?>

            <div style="display:block;color:red;background-color:rgba(251, 232, 0, 0.15);padding:5px;border:solid 1px rgba(255, 0, 9, 0.36);">
                Please <a
                        href="<?php echo add_query_arg( array( 'tab' => 'login' ), htmlentities( $_SERVER['REQUEST_URI'] ) ); ?>">Login with miniOrange</a> to configure the miniOrange SCIM User Provisioner Plugin.
            </div>
            <?php
        }
        else {
            echo '<div class="mo_scim_up_table_layout" style="padding-bottom:50px;!important">';
            audit_provisioning();   
            echo '</div></div>';
        }
}

function scim_user_management() {
    ?>
    <div class="mo_scim_up_table_layout" style="padding-bottom:50px;!important">
    <div class="mo_table_layout">
        <?php
        if ( ! mo_scim_up_is_customer_license_key_verified() ) {
            ?>
            <div style="display:block;color:red;background-color:rgba(251, 232, 0, 0.15);padding:5px;border:solid 1px rgba(255, 0, 9, 0.36);">
                Please <a href="<?php echo add_query_arg( array( 'tab' => 'login' ), htmlentities( $_SERVER['REQUEST_URI'] ) ); ?>">Login with miniOrange</a> to configure the miniOrange SCIM User Provisioner Plugin.
            </div>
            <?php
        } else {
            // Retrieve the saved subsites from the database
            $saved_subsites = get_option( 'mo_scim_selected_subsites', [] ); // Default to an empty array if not set

            // Ensure the data is an array before processing
            if ( ! is_array( $saved_subsites ) ) {
                $saved_subsites = [];
            }
            // Handle saving the selected subsites
            if ( isset( $_POST['save_subsite_selection'] ) ) {
                $selected_subsites = isset( $_POST['selected_subsites'] ) ? json_decode( stripslashes( $_POST['selected_subsites'] ), true ) : [];

                if ( ! is_array( $selected_subsites ) ) {
                    $selected_subsites = [];
                }

                // Save the selected subsites to the database
                update_option( 'mo_scim_selected_subsites', $selected_subsites );
                echo '<div class="updated"><p>Subsite selection saved successfully!</p></div>';
                $saved_subsites = $selected_subsites; // Update saved_subsites with the newly saved data
            }

            // Fetch all subsites for the current multisite instance
            $subsites = get_sites( [ 'fields' => 'ids' ] );

            ?>
            <form method="post">
                <h3>Select Subsites for SCIM User Provisioning:</h3>
                <div id="dropdown-input-wrapper">
                    <input type="text" id="subsite-input" placeholder="Search and select subsites" readonly style="width:100%; padding:10px; margin-bottom:10px; cursor:pointer;">
                    <div id="subsite-dropdown" style="display:none; border:1px solid #ccc; max-height:200px; overflow-y:auto; background:#fff; position:relative; z-index:1000;">
                        <input type="text" id="subsite-search" placeholder="Search subsites..." style="width:100%; padding:5px; margin-bottom:10px;">
                        <?php foreach ( $subsites as $subsite_id ) : ?>
                            <?php
                            $subsite_details = get_blog_details( $subsite_id );
                            $subsite_name = $subsite_details->blogname . ' (' . $subsite_details->domain . $subsite_details->path . ')';
                            ?>
                            <div class="dropdown-item" data-subsite-id="<?php echo esc_attr( $subsite_id ); ?>" style="padding:5px; cursor:pointer;">
                                <?php echo esc_html( $subsite_name ); ?>
                            </div>
                        <?php endforeach; ?>
                    </div>
                    <input type="hidden" name="selected_subsites" id="selected-subsites" value="<?php echo esc_attr( json_encode( $saved_subsites ) ); ?>">
                </div>
                <div id="selected-subsitelist" style="margin-top:10px;"></div>
                <br>
                <input type="submit" name="save_subsite_selection" value="Save Subsite Selection" class="button button-primary">
            </form>

            <script>
                document.addEventListener('DOMContentLoaded', function() {
                    const inputField = document.getElementById('subsite-input');
                    const dropdown = document.getElementById('subsite-dropdown');
                    const searchField = document.getElementById('subsite-search');
                    const selectedList = document.getElementById('selected-subsitelist');
                    const hiddenInput = document.getElementById('selected-subsites');
                    let selectedSubsites = <?php echo json_encode( $saved_subsites ); ?>;

                    // Populate initial selections
                    selectedSubsites.forEach(subsiteId => {
                        addSelectedSubsite(subsiteId);
                    });

                    // Toggle dropdown
                    inputField.addEventListener('click', function() {
                        dropdown.style.display = dropdown.style.display === 'block' ? 'none' : 'block';
                    });

                    // Add subsite to the list when clicked
                    dropdown.addEventListener('click', function(event) {
                        if (event.target.classList.contains('dropdown-item')) {
                            const subsiteId = event.target.dataset.subsiteId;
                            if (!selectedSubsites.includes(subsiteId)) {
                                selectedSubsites.push(subsiteId);
                                addSelectedSubsite(subsiteId);
                                updateHiddenInput();
                            }
                        }
                    });

                    // Remove subsite from the list when clicked
                    selectedList.addEventListener('click', function(event) {
                        if (event.target.classList.contains('remove-subsite')) {
                            const subsiteId = event.target.dataset.subsiteId;
                            selectedSubsites = selectedSubsites.filter(id => id !== subsiteId);
                            document.getElementById('selected-subsite-' + subsiteId).remove();
                            updateHiddenInput();
                        }
                    });

                    // Add selected subsite to the display list
                    function addSelectedSubsite(subsiteId) {
                        const subsiteDetails = document.querySelector(`[data-subsite-id="${subsiteId}"]`);
                        const subsiteName = subsiteDetails.textContent;
                        const subsiteElement = document.createElement('div');
                        subsiteElement.id = 'selected-subsite-' + subsiteId;
                        subsiteElement.style.display = 'flex';
                        subsiteElement.style.alignItems = 'center';
                        subsiteElement.style.marginBottom = '5px';
                        subsiteElement.innerHTML = `
                            <span style="flex-grow:1;">${subsiteName}</span>
                            <button type="button" class="remove-subsite" data-subsite-id="${subsiteId}" style="margin-left:10px;">Remove</button>
                        `;
                        selectedList.appendChild(subsiteElement);
                    }

                    // Update hidden input with selected subsites
                    function updateHiddenInput() {
                        hiddenInput.value = JSON.stringify(selectedSubsites);
                    }

                    // Filter the dropdown items based on search input
                    searchField.addEventListener('input', function() {
                        const searchTerm = searchField.value.toLowerCase();
                        const items = dropdown.querySelectorAll('.dropdown-item');
                        items.forEach(item => {
                            const subsiteName = item.textContent.toLowerCase();
                            if (subsiteName.includes(searchTerm)) {
                                item.style.display = 'block';
                            } else {
                                item.style.display = 'none';
                            }
                        });
                    });
                });
            </script>

            <style>
                .dropdown-item:hover {
                    background-color: #f1f1f1;
                }
                #subsite-input:focus {
                    outline: none;
                }
            </style>
            <?php
        }
        ?>
    </div>
    
    <?php
}
function show_attribute_mapping() {

    global $wpdb;

    ?>
    <div class="mo_table_layout">
        <?php

        if ( ! mo_scim_up_is_customer_license_key_verified() ) {
            ?>

            <div style="display:block;color:red;background-color:rgba(251, 232, 0, 0.15);padding:5px;border:solid 1px rgba(255, 0, 9, 0.36);">
                Please <a
                        href="<?php echo add_query_arg( array( 'tab' => 'login' ), htmlentities( $_SERVER['REQUEST_URI'] ) ); ?>">Login with miniOrange</a> to configure the miniOrange SCIM User Provisioner Plugin.
            </div>
            <?php
        }
        
        else
        {
            show_custom_attribute_toggle();
            show_attribute();
    }
}



function create_bearer_token(){
            $bearer_token = bin2hex(random_bytes(32)) ;
            update_site_option('mo_scim_up_bearer_token',convert_uuencode($bearer_token));
            return $bearer_token;
        }

function account_login() {
			$user = wp_get_current_user();
			?>
            <form name="f1" method="post" action="" id="mo_scim_up_goto_login_form">
                <input type="hidden" name="option" value="mo_scim_up_goto_login"/>
            </form>
            <script>
                jQuery('#mo_scim_up_goto_login').click(function () {
                    jQuery('#mo_scim_up_goto_login_form').submit();
                });
            </script>
			<?php

		}


function mo_scim_up_is_customer_license_key_verified() {
        if (function_exists("mo_saml_is_customer_license_key_verified") && mo_saml_is_customer_license_key_verified() || function_exists("NddKoYsdasadJD") && NddKoYsdasadJD() || function_exists("mo_oauth_is_clv") && mo_oauth_is_clv())
        {return 1;}
			$key         = get_site_option( 'mo_scim_up_customer_token' );
			$licenseKey  = get_site_option( 'mo_scim_up_lk' );
			$email       = get_site_option( 'mo_scim_up_admin_email' );
			$customerKey = get_site_option( 'mo_scim_up_admin_customer_key' );
			if ( ( ! $licenseKey ) || ! $email || ! $customerKey || ! is_numeric( trim( $customerKey ) ) ) {
				return 0;
			} else {
				return 1;
			}
		}

function mo_scim_user_provisioning_validate() {
    if(strpos($_SERVER['REQUEST_URI'], "/scim") !== false) {
        $get_bearer = get_site_option('mo_scim_up_bearer_token');
        $bearer_token = convert_uudecode($get_bearer);
        $bearer = getBearerToken();
        if($bearer!==$bearer_token) {
            ScimCore::throwError(401,'Unauthorized');
        }

        $post = file_get_contents('php://input');
        $json = json_decode($post, true);
        $scimUserId = '';
        $isUserProvsioningRequest = false;

        if(strpos($_SERVER['REQUEST_URI'], "/scim/Groups") !== false || strpos($_SERVER['REQUEST_URI'], "/scim/v2/Groups") !== false){
                  ScimCore::SendEmptyResponse();
        }

        if(strpos($_SERVER['REQUEST_URI'], "/scim/Users") !== false || strpos($_SERVER['REQUEST_URI'], "/scim/v2/Users") !== false){
            if(strpos($_SERVER['REQUEST_URI'],'?'))
            {
                $send_query= ScimCore::Search_filter_query($_SERVER['REQUEST_URI']);
                header("HTTP/1.1 200 OK");
                header('Content-Type: application/json;charset=utf-8');
                echo $send_query ;
                exit;
            }
            if(strpos($_SERVER['REQUEST_URI'],'?count') !==false)
            {
                $send_query= ScimCore::Search_filter_query($_SERVER['REQUEST_URI']);
                header("HTTP/1.1 200 OK");
                header('Content-Type: application/json;charset=utf-8');
                echo $send_query ;
                exit;
            }
            if(strpos($_SERVER['REQUEST_URI'], "/scim/Users/") !== false || strpos($_SERVER['REQUEST_URI'], "/scim/v2/Users/") !== false){
            $scimUserId=substr($_SERVER['REQUEST_URI'], strpos($_SERVER['REQUEST_URI'], "Users/")+6);
            $externalId =$scimUserId;
            }
            elseif ((strpos($_SERVER['REQUEST_URI'], "/scim/Users") !== false || strpos($_SERVER['REQUEST_URI'], "/scim/v2/Users") !== false) && $_SERVER['REQUEST_METHOD'] =='GET' )
            {
                $send_query= ScimCore::ListAllResoures();
                header("HTTP/1.1 200 OK");
                header('Content-Type: application/json;charset=utf-8');
                echo $send_query ;
                exit;

            }
            $isUserProvsioningRequest = true;
        }

        //('group provision: ' . $isGroupProvisioningRequest);

        if($isUserProvsioningRequest && !empty($json))
        {
            mo_scim_handle_user_request($json, $scimUserId);
        }

        if(empty( $json ) && $scimUserId !='')
        {
             $user =get_user_by( 'id', $scimUserId );

             if(strpos($_SERVER['REQUEST_METHOD'], "DELETE") !== false && !empty($scimUserId)) {
                ScimCore::deprovisionUserBasedOnMode($user, $json);
                /*
                        *
                        * Add custom logic to after user is deleted by SCIM user plugin
                        *
                */
                do_action('mo_scim_user_deprovisioned',$scimUserId);
            }

             if($user)
             {
                 $send_query = ScimCore::CreateUserSchema($user);
                header("HTTP/1.1 200 OK");
                header('Content-Type: application/json;charset=utf-8');
                echo json_encode($send_query) ;
                exit;
            }
            else
            {
                ScimCore::throwError(404,'Not Found');
            }

        }
        else
        {
            ScimCore::SendEmptyResponse();
        }
    }
}

function mo_scim_handle_group_request($json){
    //ToDo need to implement group provisioning
    $mo_scim_default_role = 'subscriber';
    //$externalId = $json['externalId'];
    if(strpos($_SERVER['REQUEST_METHOD'], "POST") !== false){
        $output_json = '{
                        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
                        "id": "'.$mo_scim_default_role.'",
                        "meta": {
                            "resourceType": "Group"                                  
                        },
                        "displayName": "'.$mo_scim_default_role.'",
                        "members": []
                    }';
        header("HTTP/1.1 200 OK");
        header('Content-Type: application/json;charset=utf-8');
        echo $output_json;
        exit;

    }
    elseif(strpos($_SERVER['REQUEST_METHOD'], "GET") !== false)  {
        if(!empty($scimGroupId)){
            // Get a group using ID
            $output_json = '{
                            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
                            "id": "'.$scimGroupId.'",
                            "meta": {
                                "resourceType": "Group"
                            },
                            "displayName": "'.$mo_scim_default_role.'",
                        }';
        header("HTTP/1.1 200 OK");
        header('Content-Type: application/json;charset=utf-8');
        echo $output_json;
        exit;

        }
        else {

            if(strpos($_SERVER['REQUEST_URI'], "filter=displayName") !== false){
                $start = strpos($_SERVER['REQUEST_URI'], '%22');
                $length = strpos($_SERVER['REQUEST_URI'], '%22', -1) - 1;
                $display_name = substr($_SERVER['REQUEST_URI'], $start, $length);

                $output_json = '{
                            "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
                            "totalResults": 1,
                            "Resources": [{
                                "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
                                "id": "'.$mo_scim_default_role.'",
                                "meta": {
                                    "resourceType": "Group"                                            
                                },
                                "displayName": "'.$display_name.'",
                            }],
                            "startIndex": 1,
                            "itemsPerPage": 20
                        }';
                header("HTTP/1.1 200 OK");
                header('Content-Type: application/json;charset=utf-8');
                echo $output_json;
                exit;
            }
        }
    } elseif (strpos($_SERVER['REQUEST_METHOD'], "PATCH") !== false ){

        return;

    }
}

function mosup_array_flatten( $nestedprefix, $json ) {
     global $rtemp;
     foreach($json as $key=>$value){
         if(is_array($value)){
             mosup_array_flatten($nestedprefix.'.'.$key,$value);
         }
         else{
             $rtemp[$nestedprefix.'.'.$key]=$value;
         }

     }
    return $rtemp;
}

function mo_scim_handle_user_request($json, $scimid){
    global $rtemp ;
    $rtemp =[];
       mosup_array_flatten('scim', $json, $rtemp );
       $raw_attributes_received=$rtemp;
       $raw_attributes_received_to_check = $rtemp;
       $username     = array_key_exists('userName',$json) ? $json['userName'] :'';
       $givenName    = array_key_exists('name',$json) ? $json['name']['givenName']:'';
       $familyName   = array_key_exists('name',$json)? $json['name']['familyName']:'';
       $email        = array_key_exists('emails',$json) ? $json['emails'][0]['value']: '';
       $display_name = array_key_exists('displayName',$json) ? $json['displayName']: '';
       $externalId   = array_key_exists('externalID',$json)? $json('externalID'): '';

       if((strpos($_SERVER['REQUEST_METHOD'], "PUT") !== false ) && !empty($scimid)) {
           $user =get_user_by('ID',$scimid);
           if(empty($user)){
               ScimCore::throwError(404,'User not found with UserID'.$scimid);
           }
           if (isset($json['active']) && '' != $json['active']){ // This is for okta
               $active = $json['active'];
           }
           else{
               $active =false;
           }
           if(($active === 'false' || empty($active))){
               ScimCore::deprovisionUserBasedOnMode($user, $json);
           }
           else {
           wp_update_user( array('ID' => $scimid, 'first_name' => $givenName,'last_name' => $familyName,'display_name'=>$display_name,'user_email'=>$email,'user_name'=>$username) );
           mo_scim_up_map_custom_attributes($scimid,$raw_attributes_received);
           update_user_meta($scimid,'mo_scim_user_status','active');
            /*
                       *
                       * Add custom logic to after user is updated by SCIM user plugin
                       *
            */
               do_action('mo_scim_user_updated',$scimid,$raw_attributes_received);
               if( get_site_option('mo_scim_transaction_log') === 'true' ){
               mo_scim_update_success($scimid, $json);
               }
           }
               header("Content-Type: application/json", true, 200);
               echo json_encode(ScimCore::CreateUserSchema(get_user_by('ID',$scimid)));
               exit;
       }
       elseif((strpos($_SERVER['REQUEST_METHOD'], "PATCH") !== false ) && !empty($scimid)) {
           ScimCore::PatchUser($json,$scimid);
       }

       elseif(strpos($_SERVER['REQUEST_METHOD'], "POST") !== false)
        {
           if(username_exists($username) || email_exists($email))
           {
               if(username_exists($username)){
                   $user = get_user_by('login', $username);
                   $uid = $user->ID;
               }
               else if(email_exists($email)){
                   $user 	= get_user_by('email', $email );
                   $uid = $user->ID;
               }
               mo_scim_up_map_custom_attributes($uid,$raw_attributes_received);
               wp_update_user( array('ID' => $uid, 'first_name' => $givenName,'last_name' => $familyName,'display_name'=>$display_name,'user_email' => $email) );
                /*
                       *
                       * Add custom logic to after user is updated by SCIM user plugin
                       *
                */
               do_action('mo_scim_user_updated',$uid,$raw_attributes_received);
               if( get_site_option('mo_scim_transaction_log') === 'true' ){
                    mo_scim_update_success($uid, $json);
               }
               $json['id'] = $uid;
               $json['meta'] = array('resourceType' => 'User');
               $json = json_encode(ScimCore::CreateUserSchema($user));
               update_user_meta($uid, 'mo_scim_user_status', 'active');
               header("HTTP/1.1 201 Created");
               header('Content-Type: application/json;charset=utf-8');
               echo $json;
               exit;
           }
           else
           {
                   if(get_site_option('mo_scim_show_attribute')=='true')
                   {
                       update_site_option('mo_scim_test_config_attrs',$raw_attributes_received);
                   }
                   $random_password = wp_generate_password( 10, false );
                   $userName=substr($username,0,50);
                   $uid = wp_create_user( $userName, $random_password, $email );
                   if($uid){
                   update_user_meta($uid, 'mo_scim_user_status', 'active');
                   mo_scim_up_map_custom_attributes($uid,$raw_attributes_received);
                   wp_update_user( array('ID' => $uid, 'first_name' => $givenName,'last_name' => $familyName,'display_name'=>$display_name) );
                   /*
                       *
                       * Add custom logic to after user is created by SCIM user plugin
                       *
                   */
                   do_action('mo_scim_user_created',$uid,$raw_attributes_received);
                   if( get_site_option('mo_scim_transaction_log') === 'true' ){
                   mo_scim_registration_success($uid, $json);
                   }
                   if ( is_multisite() ) {
                    $selected_subsites = get_option('mo_scim_selected_subsites');
                    if ( !empty($selected_subsites) && is_array($selected_subsites) ) {
                        remove_user_from_blog($uid, 1);
                        foreach ( $selected_subsites as $subsite_id ) {
                            if ( !is_user_member_of_blog($uid, $subsite_id) ) {
                                switch_to_blog($subsite_id);
                                $default_role =get_option('default_role');
                                add_user_to_blog($subsite_id, $uid, $default_role);
                                restore_current_blog();                    
                            }
                        }
                    }
                }

               $json['id'] = $uid;
               $json['meta'] = array('resourceType' => 'User');
               $json['active'] = true;
               $json = json_encode(ScimCore::CreateUserSchema(get_user_by('ID',$uid)));
               header("HTTP/1.1 201 Created");
               header('Content-Type: application/json;charset=utf-8');
               echo $json ;
               exit;
               }
           }
       }
       
}

function is_admin_user($user_id){
    global $wpdb;
    $cap = get_user_meta( $user_id, $wpdb->get_blog_prefix() . 'capabilities', true );
    if ( is_array( $cap ) && !empty( $cap['administrator'] ) )
        {return true;}
    else
        {return false;}
}

function mo_scim_up_map_custom_attributes($user_id, $attrs)
{
   if ( function_exists('bp_is_active') ) {
        mo_scim_up_map_custom_attributes_buddypress($user_id,$attrs);
   }

   if (get_site_option('mo_scim_custom_attrs_mapping')) {
        $custom_attributes = get_site_option('mo_scim_custom_attrs_mapping');
        if (@maybe_unserialize($custom_attributes)) {
            $custom_attributes = maybe_unserialize($custom_attributes);
        }
        foreach ($custom_attributes as $key => $value) {

            if (array_key_exists($value, $attrs)) {

                $is_single_valued = false;

                if(is_array($attrs[$value])){
                if (count($attrs[$value]) == 1) {
                    $is_single_valued = true;
                }
                if (!$is_single_valued) {
                    $attr_value = [];
                    foreach ($attrs[$value] as $custom_attribute_value) {
                        array_push($attr_value, $custom_attribute_value);
                    }
                    if(strpos( $key , 'bb_' ) === 0){  // to add support of buddypress integration
                            $count =1;
                            $bb_field_name = str_replace('bb_','',$key,$count);
                            xprofile_set_field_data($bb_field_name,$user_id,$attr_value);
                    }
                    update_user_meta($user_id, $key, $attr_value);
                } else {
                    if(strpos( $key , 'bb_' ) === 0){  // to add support of buddypress integration
                            $count =1;
                            $bb_field_name = str_replace('bb_','',$key,$count);
                            $revel=xprofile_set_field_data($bb_field_name,$user_id,$attrs[$value][0]);
                    }
                    else {
                    update_user_meta($user_id, $key, $attrs[$value][0]);
                    }
                } }
                else{
                    if(strpos( $key , 'bb_' ) === 0){  // to add support of buddypress integration
                            $count =1;
                            $bb_field_name = str_replace('bb_','',$key,$count);
                            $revel=xprofile_set_field_data($bb_field_name,$user_id,$attrs[$value]);
                    }
                    else{
                    update_user_meta($user_id, $key, $attrs[$value]);
                    }
                }
            }
            ////////////Enable this to check if we can delete user////////
            else {
                delete_user_meta($user_id, $key);
            }
        }
    }
}
function mo_scim_up_map_custom_attributes_buddypress($user_id, $attrs)
{
    if (get_site_option('mo_scim_custom_attrs_mapping_buddypress')) {
        $custom_attributes = get_site_option('mo_scim_custom_attrs_mapping_buddypress');
        $custom_attributes = maybe_unserialize($custom_attributes);

        foreach ($custom_attributes as $key => $value) {

            if (array_key_exists($value, $attrs)) {

                $is_single_valued = false;

                if(is_array($attrs[$value])){
                if (count($attrs[$value]) == 1) {
                    $is_single_valued = true;
                }
                if (!$is_single_valued) {
                    $attr_value = [];
                    foreach ($attrs[$value] as $custom_attribute_value) {
                        array_push($attr_value, $custom_attribute_value);
                    }

                    xprofile_set_field_data($key,$user_id,$attr_value);
                }
                else {
                    $attr_value = $attrs[$value][0];
                    foreach ($attrs[$value] as $custom_attribute_value) {
                        array_push($attr_value, $custom_attribute_value);
                    }
                    xprofile_set_field_data($key,$user_id,$attr_value);
                } }
                else{
                    $attr_value = $attrs[$value];
                    foreach ($attrs[$value] as $custom_attribute_value) {
                        array_push($attr_value, $custom_attribute_value);
                    }

                    xprofile_set_field_data($key,$user_id,$attr_value);
                }
            }
            ////////////Enable this to check if we can delete user data////////
            else {
                xprofile_delete_field_data($user_id, $key);
            }
        }
    }
}

function getAuthorizationHeader(){
        $headers = null;
        if (isset($_SERVER['Authorization'])) {
            $headers = trim($_SERVER["Authorization"]);
        }
        else if (isset($_SERVER['HTTP_AUTHORIZATION'])) { //Nginx or fast CGI
            $headers = trim($_SERVER["HTTP_AUTHORIZATION"]);
        } elseif (function_exists('apache_request_headers')) {
            $requestHeaders = apache_request_headers();
            // Server-side fix for bug in old Android versions (a nice side-effect of this fix means we don't care about capitalization for Authorization)
            $requestHeaders = array_combine(array_map('ucwords', array_keys($requestHeaders)), array_values($requestHeaders));
            //print_r($requestHeaders);
            if (isset($requestHeaders['Authorization'])) {
                $headers = trim($requestHeaders['Authorization']);
            }
        }
        if($headers === null){
            ScimCore::throwError(401,'ERROR:0005 Authorization header missing');
        }
        return $headers;
    }
/**
 * get access token from header
 * */
function getBearerToken() {
    $headers = getAuthorizationHeader();
    // HEADER: Get the access token from the header
    if (!empty($headers)) {
        if (preg_match('/Bearer\s(\S+)/', $headers, $matches)) {
            return $matches[1];
        }
    }
    return null;
}

function mo_scim_registration_success($user_id, $json){	
    $user_info = get_userdata($user_id);
    $username = $user_info->user_login;
    $mo_scim_config = new mo_scim_handler();
    $userIp = get_client_ip();

    $mo_scim_config->add_transactions($userIp, $username, mo_scim_constants::REGISTRATION_TRANSACTION, mo_scim_constants::SUCCESS, $json);
}

function mo_scim_update_success($user_id, $json) {
    $user_info = get_userdata($user_id);
    $username = $user_info->user_login;
    $mo_scim_config = new mo_scim_handler();
    $userIp = get_client_ip();

    $mo_scim_config->add_transactions($userIp, $username, mo_scim_constants::UPDATE_TRANSACTION, mo_scim_constants::SUCCESS, $json);

}

function mo_scim_delete_success($user_id, $json){
    $user_info = get_userdata($user_id);
    $username = $user_info->user_login;
    $mo_scim_config = new mo_scim_handler();
    $userIp = get_client_ip();

    $mo_scim_config->add_transactions($userIp, $username, mo_scim_constants::DELETE_TRANSACTION, mo_scim_constants::SUCCESS, $json);
}

function get_client_ip() {
    if (!empty($_SERVER['HTTP_CLIENT_IP'])) {
        return $_SERVER['HTTP_CLIENT_IP'];
    } elseif (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
        return $_SERVER['HTTP_X_FORWARDED_FOR'];
    } else {
        return $_SERVER['REMOTE_ADDR'];
    }
    return '';
}

function mo_support_user_provisioning() {
    ?>
    <div class="mo_scim_up_support_layout">
        <div>
            <h3>Support</h3>
            <p>Need any help? We can help you with configuring your Identity Provider. Just send us a query and we will
                get back to you soon.</p>
            <form method="post" action="">
                <input type="hidden" name="option" value="mo_scim_up_contact_us_query_option"/>
                <table class="mo_scim_up_settings_table">
                    <tr>
                        <td><input style="width:95%" type="email" class="mo_scim_up_table_textbox" required
                                   name="mo_scim_up_contact_us_email"
                                   value="<?php echo get_site_option( "mo_scim_up_admin_email" ); ?>"
                                   placeholder="Enter your email"></td>
                    </tr>
                    <tr>
                        <td><input type="tel" style="width:95%" id="contact_us_phone"
                                   pattern="[\+]\d{11,14}|[\+]\d{1,4}[\s]\d{9,10}" class="mo_scim_up_table_textbox"
                                   name="mo_scim_up_contact_us_phone"
                                   value="<?php echo get_site_option( 'mo_scim_up_admin_phone' ); ?>"
                                   placeholder="Enter your phone"></td>
                    </tr>
                    <tr>
                        <td><textarea class="mo_scim_up_table_textbox" style="width:95%" onkeypress="mo_scim_up_valid_query(this)"
                                      onkeyup="mo_scim_up_valid_query(this)" onblur="mo_scim_up_valid_query(this)" required
                                      name="mo_scim_up_contact_us_query" rows="4" style="resize: vertical;"
                                      placeholder="Write your query here"></textarea></td>
                    </tr>
                </table>
                <div style="text-align:center;">
                    <input type="submit" name="submit" style="margin:15px; width:120px;"
                           class="button button-primary button-large"/>
                </div>
            </form>
        </div>

    </div>
    <script>
    function myFunction() {
     var x = document.getElementById("mo_scim_idp_name").value;
    if (x=='other'){
             x='onelogin';
        }
    document.getElementById("link_to_guide").href = "https://plugins.miniorange.com/wordpress-scim-user-provisioning-with-"+x;
    }
        jQuery("#contact_us_phone").intlTelInput();
        jQuery("#phone_contact").intlTelInput();

        function mo_scim_up_valid_query(f) {
            !(/^[a-zA-Z?,.\(\)\/@ 0-9]*$/).test(f.value) ? f.value = f.value.replace(
                /[^a-zA-Z?,.\(\)\/@ 0-9]/, '') : null;
        }
    </script>
<?php }
function mo_scim_payload_view() {
    ?>

    <div  id="transactionPayload"  style="display:none;margin-top:20px; border:1px solid #ccc; padding:10px;background:#f9f9f9; width:93%">
      <h3 >Transaction Payload</h3>
      
        <div id="externalPayloadContainer" >
       <!-- Loader created using multiple <div> elements, each styled with CSS to form the loading animation -->
        <div id ="loader" class="mo-spinner"><div></div><div></div><div></div><div></div><div></div><div></div><div></div><div></div><div></div><div></div><div></div><div></div></div>
            <pre id="externalPayload" style="white-space: pre-wrap; word-wrap: break-word;"></pre>
        </div>
    </div>


<?php }
