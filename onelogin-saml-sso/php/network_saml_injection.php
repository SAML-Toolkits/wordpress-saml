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
<h1>Inject the SAML Settings on the following sites</h1>
<p>The SAML settings of the market site will be overwritten by the SAML settings defined on the Network SAML Settings</p>
<form method="post" action="edit.php?action=network_saml_injection">
<?php

wp_nonce_field('network_saml_injection_validate');

$opts = array('number' => 1000);
$sites = get_sites($opts);

echo '<table class="form-table"><tbody>';
echo '<tr><th scope="row" style="font-weight: normal;">Select/Unselect All</th><td><input type="checkbox" id="selector"></td></tr>';
foreach ($sites as $site) {
    $site_address = untrailingslashit($site->domain . $site->path);
    echo '<tr><th scope="row">'.$site_address.'</th>';
    echo '<td>';
    echo '<input class="selectable" type="checkbox" name="inject_saml_in_site[]" value="'.$site->id.'">';
    echo '</td>';
}
echo '</tbody></table>';

submit_button();

echo '</form>';

echo '
<script>
jQuery("#selector").click(function() {
  var value = jQuery(this).prop("checked");
  jQuery(".selectable").prop("checked", value);
});
</script>
';
