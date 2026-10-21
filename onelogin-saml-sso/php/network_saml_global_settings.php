<?php

if ( !function_exists( 'add_action' ) ) {
    echo 'Hi there!  I\'m just a plugin, not much I can do when called directly.';
    exit;
}

if (!current_user_can('manage_options')) {
     header("HTTP/1.0 403 Forbidden");
     echo '<h1>'.__("Access Forbidden!", 'onelogin-saml-sso').'</h1>';
     exit();
}

$title = __("Network SSO/SAML Global Settings", 'network-onelogin-saml-sso');

$option_group = 'onelogin_saml_configuration_network';

?>

<h1><?php echo esc_html($title); ?></h1>

<form method="post" action="edit.php?action=network_saml_global_settings">
<?php
    wp_nonce_field('network_saml_global_settings_validate');

    $checkedStr = get_site_option('onelogin_network_saml_global_jit')? 'checked="checked"' : '';
?>
    <table class="form-table">
        <tbody data-ol-has-click-handler="">
            <tr><th scope="row"><?php echo __("Provision user in all sites where jit is enabled");?></th>
                <td><input type="checkbox" name="global_jit" <?php echo $checkedStr;?>></td>
                <td><?php echo __("If disabled, plugin will enroll the user only in the specific site that validated the SAMLResponse. This is supposed to help environments where all sites uses the same IdP and configurations. The user will be enrolled with the role calculated on the site that processed the site, not per site logic will be executed to determine the role");?></td>
            </tr>
            <tr><th scope="row"><?php echo __("Central ACS site");?></th>
                <td><select name="acs_site">
                    <option value="0"><?php echo __("None (each site uses its own ACS URL)");?></option>
<?php
    $current_acs = (int) get_site_option('onelogin_network_saml_acs_site', 0);
    foreach (get_sites(array('number' => 1000)) as $site) {
        $address = untrailingslashit($site->domain . $site->path);
        echo '<option value="'.(int) $site->id.'"'.selected($current_acs, (int) $site->id, false).'>'.esc_html($address).'</option>';
    }
?>
                </select></td>
                <td><?php echo __("If set, all sites use the ACS URL of the selected site, so only that URL has to be registered in the IdP. After the login the user is redirected back to the site where the login started. The selected site must have SAML configured and enabled.");?></td>
            </tr>
        </tbody>
    </table>
<?php
    submit_button();

    echo '</form>';
