<?php
/**
 * Template for uploading IDP metadata.
 *
 * This template provides a form interface for uploading Identity Provider metadata
 * either via file upload or by fetching from a metadata URL.
 *
 * @package miniorange-saml-20-single-sign-on
 */
// phpcs:ignoreFile WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedVariableFound -- Template scope variables.

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\SRC\Utils\Utility;
use MOSAML\SRC\Utils\Feature_Control;

?>

<div class="mosaml-tab-content-section mosaml-margin-top-bottom-0-2-rem">
	<table class="mosaml-table-width">
		<tr>
			<td colspan="3">
				<h3>
					Upload IDP Metadata
					<span class="mosaml-cancel-button-wrapper">
						<a href="<?php echo esc_url( admin_url() . 'admin.php?page=mo_saml_settings&tab=sp_setup' ); ?>">
							<input type="button" class="button button-primary button-large" <?php echo esc_attr( $disabled_due_to_license ); ?> value="Cancel" />
						</a>
					</span>
				</h3>
			</td>
		</tr>
		<tr>
			<td colspan="4"><hr></td>
		</tr>
		
		<!-- Common Identity Provider Name Field -->
		<tr>
			<td width="25%">
				Identity Provider Name<span class="mosaml-required-field">*</span>
			</td>
			<td>
				<input 
					type="text" 
					id="saml_identity_metadata_provider_common" 
					placeholder="Identity Provider Name" 
					class="mosaml-input-full-width" 
					value="<?php echo esc_attr( $data->idp_name ); ?>" 
					required="true" 
					pattern="^(?=.*[a-zA-Z0-9])[a-zA-Z0-9\s_\-@]+$" 
					title=" Special characters are not allowed except underscore(_), hyphen(-) and @." 
				/>
			</td>
		</tr>
		<tr>
			<td>&nbsp;</td>
		</tr>
		
		<!-- File Upload Form -->
		<form id="saml_file_form" name="saml_file_form" method="post" action="<?php echo esc_url( $action_url ); ?>" enctype="multipart/form-data" onsubmit="return copyIdpName('file')">
			<input type="hidden" name="saml_edit_upload_metadata_name" value="<?php echo esc_attr( $data->idp_name ); ?>" />
			<input type="hidden" name="saml_identity_metadata_provider" id="hidden_idp_name_file" value="" />
			<input type="hidden" name="upload_metadata" value="file" />
			<input type="hidden" name="option" value="mosaml_upload_metadata_file" />
			<input type="hidden" name="idp_id" value="<?php echo esc_attr( ! empty( $data->idp_id ) ? $data->idp_id : Utility::sanitize_get_data( 'idp' ) ); ?>" />
			<?php wp_nonce_field( 'mosaml_upload_metadata_file' ); ?>
			<tr>
				<td>Upload Metadata:</td>
				<td colspan="2">
					<input type="file" name="metadata_file" required="true" />
					<input type="submit" class="button button-primary button-large" <?php echo ( $disable_new_idp ? esc_attr( Feature_Control::get_disabled_attribute( 4 ) ) : '' ); ?> <?php echo esc_attr( $disabled_due_to_license ); ?> value="Upload" />
				</td>
			</tr>
		</form>
		
		<tr>
			<td colspan="3">
				<p class="mosaml-separator-text"><b>OR</b></p>
			</td>
		</tr>
		
		<!-- URL Fetch Form -->
		<form id="saml_url_form" name="saml_url_form" method="post" action="<?php echo esc_url( $action_url ); ?>" onsubmit="return copyIdpName('url')">
			<input type="hidden" name="saml_edit_upload_metadata_name" value="<?php echo esc_attr( $data->idp_name ); ?>" />
			<input type="hidden" name="saml_identity_metadata_provider" id="hidden_idp_name_url" value="" />
			<input type="hidden" name="upload_metadata" value="url" />
			<input type="hidden" name="option" value="mosaml_fetch_metadata_url" />
			<input type="hidden" name="idp_id" value="<?php echo esc_attr( ! empty( $data->idp_id ) ? $data->idp_id : Utility::sanitize_get_data( 'idp' ) ); ?>" />
			<?php wp_nonce_field( 'mosaml_fetch_metadata_url' ); ?>
			<tr>
				<td width="20%">Enter metadata URL:</td>
				<td>
					<input 
						type="url" 
						name="metadata_url" 
						placeholder="Enter metadata URL of your IdP." 
						class="mosaml-metadata-url-input" 
						value="<?php echo esc_url( $data->metadata_url ? $data->metadata_url : '' ); ?>" 
						required="true" 
					/>
				</td>
				<td width="20%">
					&nbsp;&nbsp;<input type="submit" class="button button-primary button-large" <?php echo ( $disable_new_idp ? esc_attr( Feature_Control::get_disabled_attribute( 4 ) ) : '' ); ?> <?php echo esc_attr( $disabled_due_to_license ); ?> value="Fetch Metadata" />
				</td>
			</tr>
			<tr>
				<td colspan="3">
					<br/>
					<?php Feature_Control::start_feature_lock_container( 3 ); ?>
					<label class="switch">
						<input type="checkbox" name="sync_metadata" id="sync_metadata" value="checked" <?php echo esc_html( $data->sync_metadata ); ?> onChange="mo_saml_handle_metadata_sync_toggle()" />
						<span class="slider round"></span>
					</label>
					<span class="mo-saml-5px-padding-left"><b>Update IdP settings by pinging metadata URL ? ( We will store the metadata URL )</b></span>
					<?php Feature_Control::end_feature_lock_container( 3 ); ?>
				</td>
			</tr>
			<tr>
				<td colspan="3">
					<div id="select_time_sync_metadata" class="mo_saml_help_desc <?php echo ! empty( $data->sync_metadata ) ? '' : 'mosaml-display-none'; ?>">
						<label>
							<input type="checkbox" name="sync_certificate_metadata" id="sync_certificate_metadata" value="checked" <?php echo esc_html( $data->sync_only_certificate ); ?> />
						</label>
						<span class="mo-saml-5px-padding-left"><b>Sync Only Certificates from Metadata</b></span>
						<br style="clear:both;"/><br/>
					<span>Select how often you want to ping the IdP : </span>
					<select name="sync_time_interval" id="sync_time_interval" class="mosaml-select-field">
						<?php foreach ( Utility::get_sync_interval_options() as $key => $label ) : ?>
							<option value="<?php echo esc_attr( $key ); ?>" <?php echo ( ! empty( $data->sync_time_interval ) && $data->sync_time_interval === $key ) ? 'selected' : ''; ?>><?php echo esc_html( $label ); ?></option>
						<?php endforeach; ?>
					</select>
					</div>
				</td>
			</tr>
		</form>
	</table>
</div>
<?php
