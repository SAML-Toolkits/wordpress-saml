<?php

	function show_custom_attribute_toggle() {
		if (false === get_site_option('mo_scim_show_attribute')) {
			add_site_option('mo_scim_show_attribute', 'true');
		}
		echo '<form id="mo_scim_show_attribute" name="mo_scim_show_attribute" method="post" action ="">';
		wp_nonce_field( 'mo_scim_show_attribute' );
		echo '
    <table id="myTable_attribute_show" width="100%" border="0" style="background-color:#FFFFFF; border:1px solid #CCCCCC; padding:0px 0px 0px 10px;">
		  <tr>
			<td colspan="4">
				<h3>Attribute Mapping</h3>
           <input type="hidden" name="option" value="mo_scim_show_attribute" />
          <ol ><label class="switch"><input type="checkbox" id="scim_test" name="mo_scim_show_attribute" onChange= "document.getElementById(\'mo_scim_show_attribute\').submit()" value = "true"';
		checked( get_site_option( 'mo_scim_show_attribute' ) == 'true' );
		echo '><span class="slider round" ></span></label> <b style="left:-25px;"> Show User Attribute when a user is created.</b></ol>
        
        </form></td></tr></table>';
	}


	function show_attribute() {
		//Attribute mapping

		$idp_attrs = get_site_option( 'mo_scim_test_config_attrs' );

		if ( @maybe_unserialize( $idp_attrs ) ) {
			$idp_attrs = maybe_unserialize( $idp_attrs );
		}

		$current_user = wp_get_current_user();
		$wpum_meta    = get_user_meta( $current_user->ID );

		echo '
		<form name="scim_form_am" id="scim_form_am" method="post" action="">';
		wp_nonce_field( 'login_widget_scim_attribute_mapping' );
		echo '<input type="hidden" name="option" value="login_widget_scim_attribute_mapping" />';
		echo ' <table id="myTable" width="100%" border="0" style="background-color:#FFFFFF; border:1px solid #CCCCCC; padding:0px 0px 0px 10px;">
		  <tr>
			<td colspan="4">';

		echo '
			</td>
		  </tr>';

		$i = 0;

		echo '<tr><td colspan="3">
				Map extra IDP attributes which you wish to be included in the user profile. <p><b>NOTE: </b>Customized Attribute Mapping means you can map any attribute of the IDP to the attributes of <b>user-meta</b> table of your database.</p>
				<p>Enable the toggle for an attribute if you want to display it in the Wordpress <a href="' . get_admin_url() . 'users.php">Users</a> table.</p>
				<br/>
				<input type="button" name="add_attribute" value="Add Attribute" onClick="add_custom_attribute(this)" class="button button-primary button-large"';
		if ( ! mo_scim_up_is_customer_license_key_verified() ) {
			echo ' disabled ';
		}
		echo '><br/><br/>
			
			</td><td></td>';

		echo '<td></td></tr>

						<tr>
						<td style="text-align:left;padding-left:15px"><b>Custom Attribute Name</b></td>
						<td style= "padding-left:110px;"><b>Attribute Name from IDP</b></td>
						<td style="text-align: center;"><b>Show Attribute</b></td>
						<td></td>
						</tr>';

		$custom_attributes = get_site_option( 'mo_scim_custom_attrs_mapping' );
		if ( @maybe_unserialize( $custom_attributes ) ) {
			$custom_attributes = maybe_unserialize( $custom_attributes );
		}

		if ( ! $custom_attributes ) {
			// Display an empty row
			echo show_custom_atrribute( $i,'','',false );
			$i ++;
		} else {
			foreach ( $custom_attributes as $key => $value ) {
				if ( ! empty( $key ) ) {
					// Display the populated rows
					$attr_in_user_menu = get_site_option( 'scim_show_user_attribute' );
					$checked           = false;
					if ( $attr_in_user_menu ) {
						if ( in_array( $i,$attr_in_user_menu ) ) {
							$checked = true;
						}
					}
					echo show_custom_atrribute( $i,$key,$value,$checked );
					$i ++;
				}
			}
		}

		echo '<tr id="save_config_element">
				<td><br /><input type="submit" style="width:100px;" name="submit" value="Save"  class="button button-primary button-large"';
		if ( ! mo_scim_up_is_customer_license_key_verified() ) {
			echo 'disabled';
		}

		echo '/> &nbsp;
				<br /><br />
				</td>
			  </tr>
			 </table>
			 </form>';

		echo '<script>

			var getRows = document.getElementsByClassName("rows");
			if(getRows.length == 1){
				getRows[0].children[3].style.visibility = \'hidden\';
			} else {
				for(var row of getRows){
					row.children[3].style.visibility = \'visible\';
				}
			}
			
		
		function checkEmptyKeyandValue(o){
			var getRow = o.parentNode.parentNode;
			var child = getRow.children;
			var keys = child[0].children;
			var values = child[1].children;
			var valueField = values[0];
			var keyField = keys[0];
			var key = keyField.value;
			var val = valueField.value;
			if(!key || 0 === key.length){
				if(val.length > 0){
					keyField.setAttribute("required", "required");
				} else {
					keyField.removeAttribute("required");
				}
			}
			
			if(!val || 0 === val.length){
				if(key.length > 0){
					valueField.setAttribute("required", "required");
				} else {
					valueField.removeAttribute("required");
				}
			}
		}
		
		
		function add_custom_attribute(o){
			rows = "' . addslashes( show_custom_atrribute( $i,'','',false ) ) . '";';

		$i ++;
		echo '
			jQuery(rows).insertBefore(jQuery("#save_config_element"));
			
			if(getRows.length == 1){
				getRows[0].children[3].style.visibility = \'hidden\';
			} else {
				for(var row of getRows){
					row.children[3].style.visibility = \'visible\';
				}
			}
		}

		
		function removeRow(o){
			var thisRow = o.parentNode.parentNode;
			if(getRows.length == 2){
				if(thisRow.id === getRows[0].id){
					getRows[1].children[3].style.visibility = \'hidden\';
				}
				getRows[0].children[3].style.visibility = \'hidden\';
				
			} else {
				for(var row of getRows){
					row.children[3].style.visibility = \'visible\';
				}
			}
			
			thisRow.parentNode.removeChild(thisRow);
			
		}
			
		</script>
		<br />';
	}

	function show_custom_atrribute( $index,$key,$value,$checked ) {
		$html = '<tr id="row_' . $index . '"><td><input type="text" name="mo_scim_custom_attribute_keys[]" placeholder="Custom attribute name" value="' . $key . '" onkeyup="checkEmptyKeyandValue(this)"';
		if ( ! mo_scim_up_is_customer_license_key_verified() ) {
			$html = $html . 'disabled';
		}
		$html      = $html . '/></td>';
		$idp_attrs = get_site_option( 'mo_scim_test_config_attrs' );
		if ( @maybe_unserialize( $idp_attrs ) ) {
			$idp_attrs = maybe_unserialize( $idp_attrs );
		}

		if ( ! empty( $idp_attrs ) ) {
			$html = $html . '<td><select name="mo_scim_custom_attribute_values[]" style="width:90%"';
			if ( ! mo_scim_up_is_customer_license_key_verified() ) {
				$html = $html . 'disabled';
			}
			$html = $html . '><option value="">--Select an Attribute--</option>';
			foreach ( $idp_attrs as $attr_key => $attr_value ) {
				$selected = ( $value == $attr_key ) ? 'selected' : '';
				$html     = $html . '<option value="' . $attr_key . '" ' . $selected . ' >' . $attr_key . '</option>';
			}
			$html = $html . '</td>';
		} else {
			$html = $html . '<td><input type="text" name="mo_scim_custom_attribute_values[]" placeholder="Enter attribute name from IDP" value="' . $value . '" style="width:74%;" onkeyup="checkEmptyKeyandValue(this)"';
			if ( ! mo_scim_up_is_customer_license_key_verified() ) {
				$html = $html . 'disabled';
			}
			$html = $html . '/></td>';
		}
		$html = $html . '<td style="text-align: center; width:15%;"><label class="switch"><input type="checkbox" title="Display in Wordpress Users table" name="mo_scim_display_attribute_' . $index . '"';
		if ( $checked ) {
			$html = $html . 'checked';
		}
		$html = $html . ' value="true"';
		if ( ! mo_scim_up_is_customer_license_key_verified() ) {
			$html = $html . 'disabled';
		}
		$html = $html . '><span class="slider round"></span></label></td><td><input type="button" value="X" onClick="removeRow(this)" class="button button-primary button-large" style="float:right;" /></td></tr>';

		return $html;
	}

/////////Display_Attribute_mapping///////////
	function mo_scim_display_attrs_list() {
		$idp_attrs = get_site_option( 'mo_scim_test_config_attrs' );
		if ( @maybe_unserialize( $idp_attrs ) ) {
			$idp_attrs = maybe_unserialize( $idp_attrs );
		}

		if ( ! empty( $idp_attrs ) ) {
			echo '<div class="mo_scim_up_support_layout" style="padding-bottom:20px; padding-right:5px;">
			<h3>Attributes received from the Identity Provider:</h3>
					<div>
						<table style="border-collapse:collapse;border-spacing:0;table-layout: fixed; width: 95%;background-color:#ffffff;">
						<tr style="text-align:center;"><td style="font-weight:bold;border:1px solid #949090;padding:2%; width:65%;">ATTRIBUTE NAME</td><td style="font-weight:bold;padding:2%;border:1px solid #949090; word-wrap:break-word; width:35%;">ATTRIBUTE VALUE</td></tr>';

			foreach ( $idp_attrs as $attr_name => $values ) {
				echo '<tr style="text-align:center;"><td style="font-weight:bold;border:1px solid #949090;padding:2%; word-wrap:break-word;">' . $attr_name . '</td>';
				echo '<td style="padding:2%;border:1px solid #949090; word-wrap:break-word;">' . $values . '</td>
									</tr>';
			}
			echo '
							</table>
							<br/>
							<input type="button" class="button-primary"';
			if ( ! mo_scim_up_is_customer_license_key_verified() ) {
				echo ' disabled ';
			}
			echo 'value="Clear Attributes List" onclick="document.forms[\'scim_up_clear_attribute\'].submit();">
							<p><b>NOTE :</b> Please clear this list after configuring the plugin to delete your confidential attributes.<br/>
							Enable <b>Show Attribute</b> in <b>SCIM Configuration</b> tab to populate the list again when a user is created.</p>
							<form method="post" action="" id="scim_up_clear_attribute">';
			wp_nonce_field( 'scim_up_clear_attribute' );
			echo '<input type="hidden" name="option" value="scim_up_clear_attribute">
							</form>
							</div>
			</div>';
		}
	}