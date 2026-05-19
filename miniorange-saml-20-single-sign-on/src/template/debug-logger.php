<?php
/**
 * Debug Log template.
 *
 * @package miniorange-saml-20-single-sign-on/template
 */
// phpcs:ignoreFile WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedVariableFound -- Template scope variables.

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\SRC\Constant\Constants;

$enable_plugin_backup_on_upgrade = get_option( Constants::ENABLE_BACKUP_SETTINGS, 'checked' );
?>
<div class="mosaml-tab-content-section mosaml-margin-top-bottom-0-2-rem">
	<form action="" method="post" id="mosaml_debug_logger">
		<?php wp_nonce_field( 'mosaml_debug_logger' ); ?>
		<input type="hidden" name="option" value="mosaml_debug_logger">
		<div class="mosaml-div-flex-row mosaml-div-flex-row-space-between">
			<div>
				<h3>Debug Logger Tools</h3>
			</div>
			<div>
				<a href="<?php echo esc_url( admin_url( 'admin.php?page=mo_saml_settings' ) ); ?>" class="button button-large button-primary">
					<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="mosaml-back-icon-position" viewBox="0 0 16 16">
						<path fill-rule="evenodd" d="M15 8a.5.5 0 0 0-.5-.5H2.707l3.147-3.146a.5.5 0 1 0-.708-.708l-4 4a.5.5 0 0 0 0 .708l4 4a.5.5 0 0 0 .708-.708L2.707 8.5H14.5A.5.5 0 0 0 15 8z"></path>
					</svg>&nbsp;Back To Plugin Configuration
				</a>
			</div>
		</div>
		<hr>
		<b>If you are facing any issues with the SSO, please follow these steps for easier debugging:</b>
		<br><br>
		<div>
			<div>
				<b>Step 1:</b> Enable the Debug Logs option below and reproduce the issue.
			</div>
			<div class="mosaml-debug-logger-content">
				<div><b>miniOrange Debug Logs</b></div>
				<div class="mosaml-padding-left-6-rem">
				<label class="switch">
					<input type="checkbox" id="mo_saml_enable_debug_logs" name="mo_saml_enable_debug_logs" value="checked" onchange="this.form.submit();" <?php echo esc_attr( $debug_log_enabled ); ?> <?php echo esc_attr( isset( $license_disabled ) ? $license_disabled : '' ); ?>>
					<span class="slider round"></span>
				</label>
				</div>
			</div>
			<div class="mosaml-text-align-center">
				<input type="submit" class="button button-large button-primary" name="clear_debug_logs" value="Clear Debug Logs" title="Enable debug logs first" <?php echo esc_attr( $disabled ); ?>>
			</div>
			<div class="mosaml-debug-logger-note-container">
				<p>
					<b>
						<span class="mosaml-red-text">Note: </span>
						<u>If your wp-config.php is not writable</u>, follow the steps below to Enable debug logs Manually
					</b>
					<ul class="mosaml-list-style-disc">
						<li>Copy this code <code>define('<?php echo esc_attr( Constants::DEBUG_LOG_CONSTANT ); ?>', true);</code></li>
						<li>Paste it in the <a href="https://wordpress.org/support/article/editing-wp-config-php/" target="_blank">wp-config.php</a> file before the line <code>/* That's all, stop editing! Happy publishing. */</code> to enable the miniOrange debug logs.</li>
					</ul>
				</p>
			</div>
			<div>
				<b>Step 2:</b> Download the Debug Log File and Plugin Configurations.
			</div>
			<div class="mosaml-text-align-center mosaml-download-debug-logs-button-padding">
				<input type="submit" class="button button-large button-primary" name="download_debug_logs" value="Download Debug Logs" title="Enable debug logs first" <?php echo esc_attr( $disabled ); ?>>
			</div>
			<div>
				<b>Step 3:</b> Send the Debug Log File and Plugin Configurations to us at <a href="mailto:samlsupport@xecurify.com" class="mosaml-red-text">samlsupport@xecurify.com</a>.
			</div>
			<div class="mosaml-margin-top-1rem">
				<b>Step 4:</b> Issue Resolved? Then you can disable the debug logs and delete the Debug Log Files.
			</div>
			<div class="mosaml-text-align-center mosaml-download-debug-logs-button-padding">
				<input type="submit" class="button button-large button-primary" name="delete_debug_log_files" value="Delete Debug Log Files" title="Disable debug logs first" <?php echo esc_attr( $delete_disabled ); ?>>
			</div>
		</div>
	</form>
</div>
