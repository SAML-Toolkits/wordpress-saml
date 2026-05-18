<?php
    
function audit_provisioning(){
    $mo_scim_handler = new mo_scim_handler();
    $style = "none";
    $message = "Show Advanced Search";
    if (get_site_option('mo_scim_advanced_reports')) {
        $style = "block";
        $message = "Hide Advanced Search";
    }

    if ($style == "none") {
        $usertranscations = $mo_scim_handler->get_all_transactions();
    } else {
        $usertranscations = $mo_scim_handler->get_all_transactions_using_advanced_search();
    }
?>

<div class="mo_wpns_small_layout">
    <table>
        <tr>
            <td style="width: 100%">
                <h2>
                    User Transactions Report
                </h2>
            </td>
            <td>
                <form id="mo_scim_manual_clear" method="post" action="">
                <?php wp_nonce_field( 'mo_scim_manual_clear'); ?>
                <input type="hidden" name="option" value="mo_scim_manual_clear">
                <input type="submit" name="clearReports" style="width:100px;" value="Clear Reports" class="button button-primary button-large">
                </form>
            </td>
        </tr>
    </table>

<form id="mo_scim_hide_advanced_search" method="post" action="">
<?php wp_nonce_field( 'mo_scim_hide_advanced_search'); ?>    
    <input type="hidden" name="option" value="mo_scim_hide_advanced_search">
</form>

<p>
    <a id="advanced_search_settings"
       onclick="showAdvancedSearch()"
       style="font-size:13pt;cursor:pointer"><?php echo $message?>
    </a>
</p>
<div class="mo_wpns_small_layout" id="mo_scim_advanced_search_div" style="display: <?php echo $style ?>">
    <div style="float:right;margin-top:10px">
    <form id="mo_scim_clear_advance_search" method="post" action="">
    <?php wp_nonce_field( 'mo_scim_clear_advance_search'); ?>
        <input type="hidden" name="option" value="mo_scim_clear_advance_search">
        <input type="submit" name="clearsearch" style="width:100px;" value="Clear Search" class="button button-success button-large">
    </form>
    </div>
    <h3>Advanced Report</h3>

    <form id="mo_scim_advanced_reports" method="post" action="">
    <?php wp_nonce_field( 'mo_scim_advanced_reports'); ?>
        <input type="hidden" name="option" value="mo_scim_advanced_reports">
        <table style="width:100%">
        <tr>
        <td width="33%">WordPress Username (Optional) : <input class="mo_wpns_table_textbox" type="text" id="username" name="username" placeholder="Search by username" value="<?php echo get_site_option('mo_scim_advanced_search_username'); ?>"></td>
        <td width="33%">IP Address (Optional) :<input class="mo_wpns_table_textbox" type="text"  id="ip" name="ip" placeholder="Search by IP" value="<?php echo get_site_option('mo_scim_advanced_search_ip'); ?>"></td>
        <td width="33%">Status :
            <select name="status" id="status" style="width:100%;">
                <?php
                    $status = get_site_option('mo_scim_advanced_search_status');
                ?>
                <option value="default" <?= $status=="default" ? 'selected="selected"' : ''; ?>>All</option>
                <option value="success" <?= $status=="success" ? 'selected="selected"' : ''; ?>>Success</option>
                <option value="failed" <?= $status=="failed" ? 'selected="selected"' : ''; ?>>failed</option>
            </select>
        </td>
        </tr>
        <tr><td><br></td></tr>
        <tr>
        <td width="33%">User Action :
            <select name="user_action" id="user_action" style="width:100%;">
                <?php
                    $type = get_site_option('mo_scim_advanced_search_action');
                ?>
                <option value="User Registration" <?= $type=="User Registration" ? 'selected="selected"' : ''; ?>>User Registration</option>
                <option value="User Update" <?= $type=="User Update" ? 'selected="selected"' : ''; ?>>User Update</option>
                <option value="User Delete" <?= $type=="User Delete" ? 'selected="selected"' : ''; ?>>User Delete</option>
            </select>
        </td>
        <td width="33%">From Date (Optional) : <input class="mo_wpns_table_textbox" type="date" id="from_date" name="from_date" value="<?php echo get_site_option('mo_scim_advanced_search_from_date'); ?>"></td>
        <td width="33%">To Date (Optional) : <input class="mo_wpns_table_textbox" type="date" id="to_date" name="to_date" value="<?php echo get_site_option('mo_scim_advanced_search_to_date'); ?>"></td>
        </tr>
        </table>
        <br><input type="submit" name="Search" style="width:100px;" value="Search" class="button button-primary button-large">
    </form>
    <br>
</div>
<hr/>
<table id="reports_table" class="display" cellspacing="0" width="100%">
    <thead>
        <tr>
            <th>IP Address</th>
            <th>Username</th>
            <th>User Action</th>
            <th>Status</th>
            <th>Created Date</th>
        </tr>
    </thead>
    <tbody>
        <?php foreach($usertranscations as $usertranscation){
        echo '<tr style="text-align:center"><td style="width:20%;">'.$usertranscation->ip_address.'</td><td style="width:20%">'.$usertranscation->username.'</td><td style="width:20%">'.$usertranscation->type.'</td><td style="width:20%">';
        if($usertranscation->status==mo_scim_constants::FAILED || $usertranscation->status==mo_scim_constants::PAST_FAILED)
            echo '<span style=color:red>'.mo_scim_constants::FAILED.'</span>';
        else if($usertranscation->status==mo_scim_constants::SUCCESS)
            echo '<span style=color:green>'.mo_scim_constants::SUCCESS.'</span>';
        else
            echo "N/A";
        echo '</td><td style="width:20%">' .date("M j, Y, g:i:s a",$usertranscation->created_timestamp).'</td></tr>';
        } ?>
    </tbody>
</table>
</div>
<script>
jQuery(document).ready(function() {
    jQuery('#reports_table').DataTable({
        "order": [[ 4, "desc" ]]
    });
} );
    function showAdvancedSearch(){
        var x = document.getElementById('mo_scim_advanced_search_div');
        if (x.style.display === 'none') {
            x.style.display = 'block';
            document.getElementById('advanced_search_settings').innerHTML = "Hide Advanced Search";
        }
        else {
            x.style.display = 'none';
            document.getElementById('advanced_search_settings').innerHTML = "Show Advanced Search";
            document.getElementById('mo_scim_hide_advanced_search').submit();
        }
    }
</script>
<?php
}

?>