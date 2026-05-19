<?php // phpcs:disable Generic.Files.LineEndings.InvalidEOLChar
/**
 * IDP Metadata Sync Template
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
<div id="metadata-sync" class="mo-saml-settings-container mosaml-margin-top-bottom-0-2-rem">
	<h3>Metadata Sync Settings</h3>
	<hr>
	<div class="mo-saml-settings-internal-container">
		<form width="98%" border="0" name="saml_form_ms" method="post" action="<?php echo isset( $action_url ) ? esc_url( $action_url ) : ''; ?>">
			<?php wp_nonce_field( 'mosaml_login_widget_saml_metadata_sync' ); ?>
			<input type="hidden" name="option" value="mosaml_login_widget_saml_metadata_sync" />
			<input type="hidden" name="idp_id" value="<?php echo ! empty( $data->idp_id ) ? esc_attr( $data->idp_id ) : esc_attr( Utility::sanitize_get_data( 'idp' ) ); ?>" />
			<input type="hidden" id="is_first_time_sync" value="<?php echo ( empty( $data->sync_metadata ) && empty( $data->sync_only_certificate ) ) ? true : false; ?>" />
			<?php Feature_Control::start_feature_lock_container( 3 ); ?>
			<div class="mosaml-idp-metadata-sync-table">
				<div class="mosaml-idp-metadata-sync-row">
					<div class="mo-saml-width-200 mosaml-idp-metadata-sync-label-cell">
						<strong><b><label for="sync_metadata">Metadata Sync</label></b></strong>
					</div>
					<div class="mosaml-idp-metadata-sync-toggle-cell">
						<label class="switch">
							<input type="checkbox" name="sync_metadata" id="sync_metadata" value="checked" <?php echo esc_html( $data->sync_metadata ); ?> onChange="mo_saml_handle_metadata_sync_toggle()" />
							<span class="slider round"></span>
						</label>
					</div>
				</div>
				<div class="mosaml-idp-metadata-sync-row">
					<div class="mosaml-idp-metadata-sync-cell">&nbsp;</div>
					<div class="mosaml-idp-metadata-sync-note-cell"><b>NOTE: </b>Enabling this toggle will automatically fetch and update the metadata within a selected time period from the provided IdP's metadata URL. The metadata URL will only be stored when the toggle is active.</div>
				</div>
				<div class="mosaml-idp-metadata-sync-row">
					<div class="mosaml-idp-metadata-sync-cell">&nbsp;</div>
					<div class="mosaml-idp-metadata-sync-cell">
						<div id="select_time_sync_metadata" class="mo_saml_help_desc <?php echo ! empty( $data->sync_metadata ) ? '' : 'mosaml-display-none'; ?>">
							<input type="url" id="metadata_url" name="metadata_url" placeholder="Enter metadata URL of your IdP." class="mosaml-metadata-url-input" value="<?php echo esc_url( ! empty( $data->metadata_url ) ? $data->metadata_url : '' ); ?>" onChange="update_metadata_url_sync()" />
							<br><br>
							<label>
								<input type="checkbox" name="sync_certificate_metadata" id="sync_certificate_metadata" value="checked" <?php echo esc_html( $data->sync_only_certificate ); ?> onChange="mo_saml_handle_metadata_sync_toggle()" />
							</label>
							<span class="mo-saml-5px-padding-left"><b>Sync Only Certificates from Metadata</b></span>
							<br><br>
							<label for="sync_time_interval"><strong>Select Sync Interval:</strong></label>
							<select name="sync_time_interval" id="sync_time_interval" class="mosaml-select-field">
								<?php
								$selected_interval = ! empty( $data->sync_time_interval ) ? $data->sync_time_interval : 'daily';
								foreach ( $interval_options as $key => $label ) :
									?>
									<option value="<?php echo esc_attr( $key ); ?>" <?php echo $selected_interval === $key ? 'selected' : ''; ?>><?php echo esc_html( $label ); ?></option>
								<?php endforeach; ?>
							</select>
						</div>
						<br>
					</div>
				</div>
				<div class="mosaml-idp-metadata-sync-row">
					<div class="mosaml-idp-metadata-sync-cell">
						<input type="hidden" name="saml_edit_upload_metadata_name" value="<?php echo ! empty( $data->idp_id ) ? esc_html( $data->idp_id ) : esc_html( Utility::sanitize_get_data( 'idp' ) ); ?>" />
					</div>
					<div class="mosaml-idp-metadata-sync-cell">
						<input type="submit" name="submit" value="Save &amp; Sync Now" class="button button-primary button-large mo-saml-cancel-button" />
					</div>
				</div>
			</div>
			<?php Feature_Control::end_feature_lock_container( 3 ); ?>	
			<br/>
		</form>
	</div>
	<br/>
</div>
