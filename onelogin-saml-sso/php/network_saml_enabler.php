<?php

if (!function_exists('add_action')) {
    echo 'Hi there!  I\'m just a plugin, not much I can do when called directly.';
    exit;
}

if (!current_user_can('manage_options')) {
     header("HTTP/1.0 403 Forbidden");
     echo '<h1>'.__("Access Forbidden!", 'onelogin-saml-sso').'</h1>';
     exit();
}

?>
<h1>Enable/Disable SAML feature on the following sites</h1>

<form method="post" action="edit.php?action=network_saml_enabler">
<?php

$sites = get_sites();

echo '<table class="form-table"><tbody>';
foreach ($sites as $site) {
    $enabled = get_blog_option($site->id, 'onelogin_saml_enabled', false);

    $site_address = untrailingslashit($site->domain . $site->path);
    echo '<tr><th scope="row">'.$site_address.'</th>';
    echo '<td>';
    echo '<input type="checkbox" name="enable_saml_in_site[]" '.($enabled ? 'checked="checked"' : ""). ' value="'.$site->id.'" '.$enabled.'>';
    echo '</td>';
}
echo '</tbody></table>';

submit_button();

echo '</form>';
