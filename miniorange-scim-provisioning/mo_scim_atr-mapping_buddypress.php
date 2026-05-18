<?php

	function mo_scim_display_attrs_list_buddypress() {
		//Attribute mapping

		$idp_attrs = get_site_option( 'mo_scim_test_config_attrs' );

		if ( @maybe_unserialize( $idp_attrs ) ) {
			$idp_attrs = maybe_unserialize( $idp_attrs );
		}

		$current_user = wp_get_current_user();
		$wpum_meta    = get_user_meta( $current_user->ID );
		echo '
		<form name="scim_form_am2" method="post" action="">';
		wp_nonce_field( 'login_widget_scim_attribute_mapping_buddypress' );
		echo '<input type="hidden" name="option" value="login_widget_scim_attribute_mapping_buddypress" />
		<table id="myTable" width="100%" border="0" style="background-color:#FFFFFF; border:1px solid #CCCCCC; padding:0px 0px 0px 10px;">
		  <tr>
			<td colspan="4">
				<h3>BuddyPress Custom Attributes</h3><hr>
			</td>
		  </tr>';

		$i = 0;

		echo '<tr><td colspan="3">
                Map SAML attribute with the BuddyPress attributes which you wish to be included in the user profile. <p><b>NOTE: </b>You can check the Test Configuration results to get a better idea as to which values to map here.
				Once the Test Configuration is successful you can configure Attribute Name from Test configuration window to BuddyPress.</p>
				<br/>
				<input type="button" name="add_attribute" value="Add Attribute" onClick="add_custom_attribute_bp(this)" class="button button-primary button-large"';
		if ( ! mo_scim_up_is_customer_license_key_verified() ) {
			echo ' disabled ';
		}

		echo '><br/><br/>
			
			</td><td></td>';

		echo '<td></td></tr>

						<tr>
						<td style="text-align:left;padding-left:15px"><b>Buddypress Attribute Name</b></td>
						<td style= "padding-left:120px;"><b>Attribute Name from IDP</b></td>
						
						
						</tr>';

		$custom_attributes = get_site_option( 'mo_scim_custom_attrs_mapping_buddypress' );
		if ( @maybe_unserialize( $custom_attributes ) ) {
			$custom_attributes = maybe_unserialize( $custom_attributes );
		}

		if ( ! $custom_attributes ) {
			// Display an empty row
			echo show_custom_attribute_bp( $i,'','',false );
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
					echo show_custom_attribute_bp( $i,$key,$value,$checked );
					$i ++;
				}
			}
		}

		echo '<tr id="save_config_element_bp">
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
		
		
		function add_custom_attribute_bp(o){
			rows = "' . addslashes( show_custom_attribute_bp( $i,'','',false ) ) . '";';

		$i ++;
		echo '
			jQuery(rows).insertBefore(jQuery("#save_config_element_bp"));
			
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

	function show_custom_attribute_bp( $index,$key,$value,$checked ) {
		$html = '<tr id="row_' . $index . '"><td><select name="mo_scim_custom_attribute_keys_bp[]" id="mo_scim_custom_attribute_keys_bp[]">';

		global $wpdb;
		$bp_xprofile_fields = $wpdb->prefix . "bp_xprofile_fields";
		$reg_bp             = $wpdb->get_results( "SELECT * FROM $bp_xprofile_fields WHERE parent_id = 0;" );

		if ( ! empty( $key ) ) {
			foreach ( $reg_bp as $field ) {
				$selected = $key == $field->name ? 'selected' : '';

				$html .= "<option value='" . $field->name . "' " . $selected . ">" . $field->name;
				$html .= "</option>";
			}
		} else {
			foreach ( $reg_bp as $field ) {
				$html .= "<option value='" . $field->name . "'>" . $field->name;
				$html .= "</option>";
			}
		}

		$html = $html . '</select></td>';

		if ( ! mo_scim_up_is_customer_license_key_verified() ) {
			$html = $html . 'disabled';
		}

		$idp_attrs = get_site_option( 'mo_scim_test_config_attrs' );
		if ( @maybe_unserialize( $idp_attrs ) ) {
			$idp_attrs = maybe_unserialize( $idp_attrs );
		}

		if ( ! empty( $idp_attrs ) ) {
			$html = $html . '<td><select name="mo_scim_custom_attribute_values_bp[]" style="width:90%"';
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
			$html = $html . '<td><input type="text" name="mo_scim_custom_attribute_values_bp[]" placeholder="Enter attribute name from IDP" value="' . $value . '" style="width:74%;" onkeyup="checkEmptyKeyandValue(this)"';
			if ( ! mo_scim_up_is_customer_license_key_verified() ) {
				$html = $html . 'disabled';
			}
			$html = $html . '/></td>';
		}
		if ( ! mo_scim_up_is_customer_license_key_verified() ) {
			$html = $html . 'disabled';
		}

		$html = $html . '<td><input type="button" value="X" onClick="removeRow(this)" class="button button-primary button-large" style= "left:-500px;" /></td></tr>';

		//style="float:right;"
		return $html;
	}