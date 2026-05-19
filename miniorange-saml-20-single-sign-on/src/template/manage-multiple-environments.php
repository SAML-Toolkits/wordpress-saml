<?php
/**
 * Multiple Environments Management Template
 *
 * @package miniorange-saml-20-single-sign-on
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\SRC\Constant\Constants;
use MOSAML\SRC\Utils\Feature_Control;

?>
<div class="mosaml-tab-content-section mosaml-margin-top-bottom-0-2-rem">
	<div class="mosaml-div-flex-row mosaml-div-flex-row-space-between">
		<div>
			<h3>Manage Multiple Environments</h3>
		</div>
		<div>
			<a href="<?php echo esc_url( $plugin_config_url ); ?>" class="button button-large button-primary">
				<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="mosaml-back-icon-position" viewBox="0 0 16 16">
					<path fill-rule="evenodd" d="M15 8a.5.5 0 0 0-.5-.5H2.707l3.147-3.146a.5.5 0 1 0-.708-.708l-4 4a.5.5 0 0 0 0 .708l4 4a.5.5 0 0 0 .708-.708L2.707 8.5H14.5A.5.5 0 0 0 15 8z"></path>
				</svg>&nbsp;Back To Plugin Configuration
			</a>
		</div>
	</div>
	<hr>
	[<a href="<?php echo esc_url( Constants::MULTIPLE_ENVIRONMENTS_DOC_URL ); ?>" target="_blank">Click here</a> to know how this is useful]
	<br>
	<div class="mosaml-div-display-flex">
		<b>Steps to add configuration for Environments</b>
		<a href="<?php echo esc_url( Constants::MULTIPLE_ENVIRONMENTS_VIDEO_URL ); ?>" target="_blank" rel="noopener noreferrer" class="mosaml-no-outline-link">
		<span class="mosaml-youtube-icon">
			<svg viewBox="0 0 16 16" xmlns="http://www.w3.org/2000/svg" fill="none">
				<path fill="red" d="M14.712 4.633a1.754 1.754 0 00-1.234-1.234C12.382 3.11 8 3.11 8 3.11s-4.382 0-5.478.289c-.6.161-1.072.634-1.234 1.234C1 5.728 1 8 1 8s0 2.283.288 3.367c.162.6.635 1.073 1.234 1.234C3.618 12.89 8 12.89 8 12.89s4.382 0 5.478-.289a1.754 1.754 0 001.234-1.234C15 10.272 15 8 15 8s0-2.272-.288-3.367z"/>
				<path fill="#ffffff" d="M6.593 10.11l3.644-2.098-3.644-2.11v4.208z"/>
			</svg>
		</span>
		</a>
	</div>

	<div>
		<ol class="mosaml-list-style-number">
			<li>Enable the Multiple Environments option.</li>
			<li>
				Configure the Environment Name and the Site URL for the Environment. 
				[ <span class="mosaml-link-text" id="mo_saml_show_site_url">How do I get the site URL?</span> ]
				<ol class="mosaml-list-style-lower-alpha" id="mo_saml_site_url_steps" style="display: none;">
				<li>Navigate to the <b>Settings -> General</b> from the sidebar of your WordPress site.</li>
				<li>Copy the <b>Site Address (URL)</b> and paste it in the Site URL for the Environment.</li>
				<li>Similarly you can add the other environments.</li>
				</ol>
			</li>
			<li>Now go to the plugin configuration page and you will see the option to select the environment.</li>
			<li>Select the environment name and complete the configurations.</li>
		</ol>
	</div>
	<hr>
	<br>

	<div>
		<?php Feature_Control::start_feature_lock_container( 4 ); ?>
		<form method="post" action="" id="manage_multiple_environments">
			<?php wp_nonce_field( 'mosaml_multiple_environment' ); ?>
			<input type="hidden" name="option" value="mosaml_multiple_environment"/>

			<label class="switch">
				<input type="checkbox" id="mosaml_enable_multiple_environments" name="enable_multiple_environments" value="checked" <?php echo esc_attr( $enable_multiple_environments ); ?> onchange="submit();" />
				<span class="slider round"></span>
			</label>
			<span class="mosaml-toggle-text-margin">
				<b>Enable Multiple Environments</b><br>
			</span>
			<div class="mo_saml_help_desc">
				By enabling this option, you can add, edit, or delete multiple environments, allowing smooth migration from one environment to another. <br>
			</div>
		</form>
		<div class="mosaml-environment-table-container">
			<form id="environment_form" method="post">
				<?php $environment_list_table->search_box( 'Search', 'search_environment' ); ?>
				<?php $environment_list_table->display(); ?>
			</form>
		</div>
		<br>
		<button class="button button-primary button-large" onclick="AddNewEnvironmentModal()" <?php echo esc_attr( $disable_multiple_environment_option ); ?>>Add New Environment</button>
		<br>
		<?php Feature_Control::end_feature_lock_container( 4 ); ?>
	</div>
	<div id="mosaml_environment_modal" class="mosaml-modal">
		<div class="mosaml-modal-content">
			<span class="mosaml-close" onclick="closeEnvironmentModal()">&times;</span>
			<form id="mosaml_environment_data_form" method="post" action="">
				<?php wp_nonce_field( 'mosaml_save_environment' ); ?>
				<input type="hidden" name="option" value="mosaml_save_environment"/>
				<input type="hidden" name="environment_id" id="mosaml_environment_id">
				<input type="hidden" name="submit_type" id="mosaml_environment_submit_type">
				<div id="add_environment_form" style="display: none;">
					<h3>Add New Environment</h3>
					<div class="mo_saml_help_desc">
						<span class="mosaml-note-red-text">Please make sure your environment URL is correct, otherwise SSO might break when migrating the settings.</span>
					</div>
					<hr>
					<div class="mosaml-modal-form-group">
						<label for="mosaml_add_environment_name"><b>Environment Name: <span class="mosaml-note-red-text">*</span></b></label>
						<input type="text" id="mosaml_add_environment_name" name="environment_name" required placeholder="Example: Prod, Staging, etc" <?php echo esc_attr( $disable_multiple_environment_option ); ?>>
					</div>

					<div class="mosaml-modal-form-group">
						<label for="mosaml_add_environment_url"><b>Environment URL: <span class="mosaml-note-red-text">*</span></b></label>
						<input type="url" id="mosaml_add_environment_url" name="environment_url" required placeholder="Example: https://example.com" <?php echo esc_attr( $disable_multiple_environment_option ); ?>>
					</div>

					<div class="mosaml-modal-actions">
						<button type="button" class="button button-primary button-large" onclick="saveEnvironment()" <?php echo esc_attr( $disable_multiple_environment_option ); ?>>Save</button>
						<button type="button" class="button button-large" onclick="closeEnvironmentModal()" <?php echo esc_attr( $disable_multiple_environment_option ); ?>>Cancel</button>
					</div>
				</div>
				<div id="edit_environment_form" style="display: none;">
					<h3>Edit Environment Details</h3>
					<div class="mo_saml_help_desc">
						<span class="mosaml-note-red-text">Please make sure your environment URL is correct, otherwise SSO might break when migrating the settings.</span>
					</div>
					<hr>
					<div class="mosaml-modal-form-group">
						<label for="mosaml_edit_environment_name"><b>Environment Name: <span class="mosaml-note-red-text">*</span></b></label>
						<input type="text" id="mosaml_edit_environment_name" name="environment_name" required placeholder="Example: Prod, Staging, etc" <?php echo esc_attr( $disable_multiple_environment_option ); ?>>
					</div>

					<div class="mosaml-modal-form-group">
						<label for="mosaml_edit_environment_url"><b>Environment URL: <span class="mosaml-note-red-text">*</span></b></label>
						<input type="url" id="mosaml_edit_environment_url" name="environment_url" required placeholder="Example: https://example.com" <?php echo esc_attr( $disable_multiple_environment_option ); ?>>
					</div>

					<div class="mosaml-modal-actions">
						<button type="button" class="button button-primary button-large" onclick="saveEnvironment()" <?php echo esc_attr( $disable_multiple_environment_option ); ?>>Update</button>
						<button type="button" class="button button-large" onclick="closeEnvironmentModal()" <?php echo esc_attr( $disable_multiple_environment_option ); ?>>Cancel</button>
					</div>
				</div>
				<div id="delete_environment_form" style="display: none;">
					<h3>Delete Environment</h3>
					<hr>
					<p class="mosaml-idp-list-label">Are you sure you want to delete the environment <b id="mosaml_delete_environment_name"></b>?</p>
					<div id="mosaml_delete_environment_idp_section" style="display: none;">
						<p class="mosaml-idp-list-label">Following IDPs are configured under this environment:</p>
						<ol id="mosaml_delete_environment_idp_list" class="mosaml-idp-list"></ol>
					</div>
					<div class="mosaml-modal-actions">
						<button type="button" id="mosaml_delete_environment_button" class="button button-primary button-large" onclick="saveEnvironment()" <?php echo esc_attr( $disable_multiple_environment_option ); ?>>Delete</button>
						<button type="button" class="button button-large" onclick="closeEnvironmentModal()" <?php echo esc_attr( $disable_multiple_environment_option ); ?>>Cancel</button>
					</div>
				</div>
			</form>
		</div>
	</div>
</div>
