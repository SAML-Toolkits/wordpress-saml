<?php
/**
 * This file contains the HTML code for the SP Metadata tab.
 *
 * @package MOSAML
 * @subpackage MOSAML/src/template
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\SRC\Constant\Constants;
use MOSAML\SRC\Utils\Feature_Control;
use MOSAML\SRC\Utils\Utility;

?>
<div class="mosaml-tab-content-section mosaml-margin-top-bottom-0-2-rem">
	<?php Feature_Control::check_plugin_state(); ?>
	<h3>Configure your Identity Provider</h3>
	<h4>Provide this plugin information to your Identity Provider team. You can choose any one of the below options:</h4>
	<?php if ( $show_point_a ) : ?>
		<p><b>a) Provide this metadata URL to your Identity Provider </b></p>
		<p style="margin-left: 2%"><code><b><a id="metadata_url" target="_blank" href="<?php echo esc_url( site_url() . Constants::METADATA_URL ); ?>"><?php echo esc_url( site_url() . Constants::METADATA_URL ); ?></a></b></code>
			<i class="mo_copy copytooltip" style="float:none" onclick="copyToClipboard(this, '#metadata_url', '#metadata_url_copy');"><svg viewBox="0 0 512 512" xmlns="http://www.w3.org/2000/svg">
					<path d="M502.6 70.63l-61.25-61.25C435.4 3.371 427.2 0 418.7 0H255.1c-35.35 0-64 28.66-64 64l.0195 256C192 355.4 220.7 384 256 384h192c35.2 0 64-28.8 64-64V93.25C512 84.77 508.6 76.63 502.6 70.63zM464 320c0 8.836-7.164 16-16 16H255.1c-8.838 0-16-7.164-16-16L239.1 64.13c0-8.836 7.164-16 16-16h128L384 96c0 17.67 14.33 32 32 32h47.1V320zM272 448c0 8.836-7.164 16-16 16H63.1c-8.838 0-16-7.164-16-16L47.98 192.1c0-8.836 7.164-16 16-16H160V128H63.99c-35.35 0-64 28.65-64 64l.0098 256C.002 483.3 28.66 512 64 512h192c35.2 0 64-28.8 64-64v-32h-47.1L272 448z" />
				</svg><span id="metadata_url_copy" class="copytooltiptext">Copy to Clipboard</span></i>
		</p>
	<?php endif; ?>
	<p><b><?php echo esc_html( $point_b ); ?>) Download the Plugin XML metadata and upload it on your Identity Provider </b></p>
	<p>
	<form method="post" action="">
		<?php wp_nonce_field( 'mosaml_download_metadata' ); ?>
		<input type="hidden" name="option" value="mosaml_download_metadata" />
		<input type="submit" class="button button-primary button-large" value="Download XML Metadata" style="margin-left: 2%" <?php echo esc_attr( $disabled_due_to_license ); ?> />
	</form>
	</p>
	<p><b><?php echo esc_html( $point_c ); ?>) Provide the following information to your Identity Provider.</b></p>

	<table border="1" style="background-color:#FFFFFF; border:1px solid #CCCCCC; padding:0px 0px 0px 10px; margin:2px; border-collapse: collapse; width:98%">

		<form method="post" action="" name="mo_saml_download">
			<?php wp_nonce_field( 'mosaml_download_cert' ); ?>
			<input type="hidden" name="option" value="mosaml_download_cert" />
		</form>
		<tr>
			<td style="width:40%; padding: 15px;"><b>SP-EntityID / Issuer</b></td>
			<td style="width:60%; padding: 15px;">
				<table width="100%">
					<tr>
						<td><span id="entity_id"><?php echo esc_html( $sp_endpoints->sp_entity_id ); ?></span></td>
						<td><i class="mo_copy copytooltip" onclick="copyToClipboard(this, '#entity_id', '#entity_id_copy');"><svg viewBox="0 0 512 512" xmlns="http://www.w3.org/2000/svg">
									<path d="M502.6 70.63l-61.25-61.25C435.4 3.371 427.2 0 418.7 0H255.1c-35.35 0-64 28.66-64 64l.0195 256C192 355.4 220.7 384 256 384h192c35.2 0 64-28.8 64-64V93.25C512 84.77 508.6 76.63 502.6 70.63zM464 320c0 8.836-7.164 16-16 16H255.1c-8.838 0-16-7.164-16-16L239.1 64.13c0-8.836 7.164-16 16-16h128L384 96c0 17.67 14.33 32 32 32h47.1V320zM272 448c0 8.836-7.164 16-16 16H63.1c-8.838 0-16-7.164-16-16L47.98 192.1c0-8.836 7.164-16 16-16H160V128H63.99c-35.35 0-64 28.65-64 64l.0098 256C.002 483.3 28.66 512 64 512h192c35.2 0 64-28.8 64-64v-32h-47.1L272 448z" />
								</svg><span id="entity_id_copy" class="copytooltiptext">Copy to Clipboard</span></i></td>
					</tr>
				</table>
			</td>

		</tr>
		<tr>
			<td style="width:40%; padding: 15px;"><b>ACS (AssertionConsumerService) URL</b></td>
			<td style="width:60%;  padding: 15px;">
				<table width="100%">
					<tr>
						<td><span id="base_url"><?php echo esc_url( $sp_endpoints->sp_base_url ); ?>/</span></td>
						<td><i class="mo_copy copytooltip" onclick="copyToClipboard(this, '#base_url', '#base_url_copy');"><svg viewBox="0 0 512 512" xmlns="http://www.w3.org/2000/svg">
									<path d="M502.6 70.63l-61.25-61.25C435.4 3.371 427.2 0 418.7 0H255.1c-35.35 0-64 28.66-64 64l.0195 256C192 355.4 220.7 384 256 384h192c35.2 0 64-28.8 64-64V93.25C512 84.77 508.6 76.63 502.6 70.63zM464 320c0 8.836-7.164 16-16 16H255.1c-8.838 0-16-7.164-16-16L239.1 64.13c0-8.836 7.164-16 16-16h128L384 96c0 17.67 14.33 32 32 32h47.1V320zM272 448c0 8.836-7.164 16-16 16H63.1c-8.838 0-16-7.164-16-16L47.98 192.1c0-8.836 7.164-16 16-16H160V128H63.99c-35.35 0-64 28.65-64 64l.0098 256C.002 483.3 28.66 512 64 512h192c35.2 0 64-28.8 64-64v-32h-47.1L272 448z" />
								</svg><span id="base_url_copy" class="copytooltiptext">Copy to Clipboard</span></i></td>
					</tr>
				</table>
			</td>

		</tr>

		<tr>
			<td style="width:40%; padding: 15px;"><b>Single Logout URL</b></td>
			<td style="width:60%;  padding: 15px;">
				<table width="100%">
					<tr>
						<td><span id="slo_url"><?php echo esc_url( $sp_endpoints->sp_base_url ); ?>/</span></td>
						<td><i class="mo_copy copytooltip" onclick="copyToClipboard(this, '#slo_url', '#slo_url_copy');"><svg viewBox="0 0 512 512" xmlns="http://www.w3.org/2000/svg">
									<path d="M502.6 70.63l-61.25-61.25C435.4 3.371 427.2 0 418.7 0H255.1c-35.35 0-64 28.66-64 64l.0195 256C192 355.4 220.7 384 256 384h192c35.2 0 64-28.8 64-64V93.25C512 84.77 508.6 76.63 502.6 70.63zM464 320c0 8.836-7.164 16-16 16H255.1c-8.838 0-16-7.164-16-16L239.1 64.13c0-8.836 7.164-16 16-16h128L384 96c0 17.67 14.33 32 32 32h47.1V320zM272 448c0 8.836-7.164 16-16 16H63.1c-8.838 0-16-7.164-16-16L47.98 192.1c0-8.836 7.164-16 16-16H160V128H63.99c-35.35 0-64 28.65-64 64l.0098 256C.002 483.3 28.66 512 64 512h192c35.2 0 64-28.8 64-64v-32h-47.1L272 448z" />
								</svg><span id="slo_url_copy" class="copytooltiptext">Copy to Clipboard</span></i></td>
					</tr>
				</table>
			</td>

		</tr>


		<tr>
			<td style="width:40%; padding: 15px;"><b>Audience URI</b></td>
			<td style="width:60%; padding: 15px;">
				<table width="100%">
					<tr>
						<td><span id="audience"><?php echo esc_html( $sp_endpoints->sp_entity_id ); ?></span></td>
						<td><i class="mo_copy copytooltip" onclick="copyToClipboard(this, '#audience', '#audience_copy');"><svg viewBox="0 0 512 512" xmlns="http://www.w3.org/2000/svg">
									<path d="M502.6 70.63l-61.25-61.25C435.4 3.371 427.2 0 418.7 0H255.1c-35.35 0-64 28.66-64 64l.0195 256C192 355.4 220.7 384 256 384h192c35.2 0 64-28.8 64-64V93.25C512 84.77 508.6 76.63 502.6 70.63zM464 320c0 8.836-7.164 16-16 16H255.1c-8.838 0-16-7.164-16-16L239.1 64.13c0-8.836 7.164-16 16-16h128L384 96c0 17.67 14.33 32 32 32h47.1V320zM272 448c0 8.836-7.164 16-16 16H63.1c-8.838 0-16-7.164-16-16L47.98 192.1c0-8.836 7.164-16 16-16H160V128H63.99c-35.35 0-64 28.65-64 64l.0098 256C.002 483.3 28.66 512 64 512h192c35.2 0 64-28.8 64-64v-32h-47.1L272 448z" />
								</svg><span id="audience_copy" class="copytooltiptext">Copy to Clipboard</span></i></td>
					</tr>
				</table>
			</td>

		</tr>
		<tr>
			<td style="width:40%; padding: 15px;"><b>NameID format</b></td>
			<td style="width:60%; padding: 15px;">
				<table width="100%">
					<tr>
						<td><span id="nameid">urn:oasis:names:tc:SAML:<?php echo esc_html( Constants::NAMEID_FORMATS['unspecified'] ); ?></span></td>
						<td><i class="mo_copy copytooltip" onclick="copyToClipboard(this, '#nameid', '#nameid_copy');"><svg viewBox="0 0 512 512" xmlns="http://www.w3.org/2000/svg">
									<path d="M502.6 70.63l-61.25-61.25C435.4 3.371 427.2 0 418.7 0H255.1c-35.35 0-64 28.66-64 64l.0195 256C192 355.4 220.7 384 256 384h192c35.2 0 64-28.8 64-64V93.25C512 84.77 508.6 76.63 502.6 70.63zM464 320c0 8.836-7.164 16-16 16H255.1c-8.838 0-16-7.164-16-16L239.1 64.13c0-8.836 7.164-16 16-16h128L384 96c0 17.67 14.33 32 32 32h47.1V320zM272 448c0 8.836-7.164 16-16 16H63.1c-8.838 0-16-7.164-16-16L47.98 192.1c0-8.836 7.164-16 16-16H160V128H63.99c-35.35 0-64 28.65-64 64l.0098 256C.002 483.3 28.66 512 64 512h192c35.2 0 64-28.8 64-64v-32h-47.1L272 448z" />
								</svg><span id="nameid_copy" class="copytooltiptext">Copy to Clipboard</span></i></td>
					</tr>
				</table>
			</td>

		</tr>
		<tr>
			<td style="width:40%; padding: 15px;"><b>Recipient URL</b></td>
			<td style="width:60%;  padding: 15px;">
				<table width="100%">
					<tr>
						<td><span id="recipient"><?php echo esc_url( $sp_endpoints->sp_base_url ); ?>/</span></td>
						<td><i class="mo_copy copytooltip" onclick="copyToClipboard(this, '#recipient', '#recipient_copy');"><svg viewBox="0 0 512 512" xmlns="http://www.w3.org/2000/svg">
									<path d="M502.6 70.63l-61.25-61.25C435.4 3.371 427.2 0 418.7 0H255.1c-35.35 0-64 28.66-64 64l.0195 256C192 355.4 220.7 384 256 384h192c35.2 0 64-28.8 64-64V93.25C512 84.77 508.6 76.63 502.6 70.63zM464 320c0 8.836-7.164 16-16 16H255.1c-8.838 0-16-7.164-16-16L239.1 64.13c0-8.836 7.164-16 16-16h128L384 96c0 17.67 14.33 32 32 32h47.1V320zM272 448c0 8.836-7.164 16-16 16H63.1c-8.838 0-16-7.164-16-16L47.98 192.1c0-8.836 7.164-16 16-16H160V128H63.99c-35.35 0-64 28.65-64 64l.0098 256C.002 483.3 28.66 512 64 512h192c35.2 0 64-28.8 64-64v-32h-47.1L272 448z" />
								</svg><span id="recipient_copy" class="copytooltiptext">Copy to Clipboard</span></i></td>
					</tr>
				</table>
			</td>

		</tr>
		<tr>
			<td style="width:40%; padding: 15px;"><b>Destination URL</b></td>
			<td style="width:60%;  padding: 15px;">
				<table width="100%">
					<tr>
						<td><span id="destination"><?php echo esc_url( $sp_endpoints->sp_base_url ); ?>/</span></td>
						<td><i class="mo_copy copytooltip" onclick="copyToClipboard(this, '#destination', '#destination_copy');"><svg viewBox="0 0 512 512" xmlns="http://www.w3.org/2000/svg">
									<path d="M502.6 70.63l-61.25-61.25C435.4 3.371 427.2 0 418.7 0H255.1c-35.35 0-64 28.66-64 64l.0195 256C192 355.4 220.7 384 256 384h192c35.2 0 64-28.8 64-64V93.25C512 84.77 508.6 76.63 502.6 70.63zM464 320c0 8.836-7.164 16-16 16H255.1c-8.838 0-16-7.164-16-16L239.1 64.13c0-8.836 7.164-16 16-16h128L384 96c0 17.67 14.33 32 32 32h47.1V320zM272 448c0 8.836-7.164 16-16 16H63.1c-8.838 0-16-7.164-16-16L47.98 192.1c0-8.836 7.164-16 16-16H160V128H63.99c-35.35 0-64 28.65-64 64l.0098 256C.002 483.3 28.66 512 64 512h192c35.2 0 64-28.8 64-64v-32h-47.1L272 448z" />
								</svg><span id="destination_copy" class="copytooltiptext">Copy to Clipboard</span></i></td>
					</tr>
				</table>
			</td>

		</tr>
		<tr>
			<td style="width:40%; padding: 15px;"><b>Default Relay State (Optional)</b></td>
			<td style="width:60%;  padding: 15px;">
				<table width="100%">
					<tr>
						<td><span id="relaystate"><?php echo esc_url( $sp_endpoints->sp_base_url ); ?>/</span></td>
						<td><i class="mo_copy copytooltip" onclick="copyToClipboard(this, '#relaystate', '#relaystate_copy');"><svg viewBox="0 0 512 512" xmlns="http://www.w3.org/2000/svg">
									<path d="M502.6 70.63l-61.25-61.25C435.4 3.371 427.2 0 418.7 0H255.1c-35.35 0-64 28.66-64 64l.0195 256C192 355.4 220.7 384 256 384h192c35.2 0 64-28.8 64-64V93.25C512 84.77 508.6 76.63 502.6 70.63zM464 320c0 8.836-7.164 16-16 16H255.1c-8.838 0-16-7.164-16-16L239.1 64.13c0-8.836 7.164-16 16-16h128L384 96c0 17.67 14.33 32 32 32h47.1V320zM272 448c0 8.836-7.164 16-16 16H63.1c-8.838 0-16-7.164-16-16L47.98 192.1c0-8.836 7.164-16 16-16H160V128H63.99c-35.35 0-64 28.65-64 64l.0098 256C.002 483.3 28.66 512 64 512h192c35.2 0 64-28.8 64-64v-32h-47.1L272 448z" />
								</svg><span id="relaystate_copy" class="copytooltiptext">Copy to Clipboard</span></i></td>
					</tr>
				</table>
			</td>

		</tr>
		<tr>
			<td style="width:40%; padding: 15px;"><b>WP Service Provider Certificate (Optional)</b></td>
			<td style="width:60%;  padding: 15px;">
				<?php Feature_Control::start_feature_lock_container( 2 ); ?>
				<input type="button" class="button button-primary" value="Download" onclick="document.forms['mo_saml_download'].submit()" <?php echo esc_attr( $disabled_due_to_license ); ?>/>
				<?php Feature_Control::end_feature_lock_container( 2 ); ?>
			</td>
		</tr>
	</table>

	<br><br>
</div>
<div class="mo-saml-settings-container mosaml-margin-top-bottom-0-2-rem">
	<h3>Service Provider Endpoints</h3>
	<hr>
	<br>
	<div class="mo-saml-settings-internal-container">
		<form method="post" id="mosaml_edit_sp_metadata_form" action="">
			<?php wp_nonce_field( 'mosaml_edit_sp_metadata' ); ?>
			<input type="hidden" name="option" value="mosaml_edit_sp_metadata" />
			<table width="98%">
				<tr>
					<td width="20%"><b>SP Base URL</b></td>
					<td width="70%">
						<?php Feature_Control::start_feature_lock_container( 2 ); ?>
						<input type="text" name="mo_saml_sp_base_url" placeholder="You site base URL" style="width: 95%;" pattern="^[^\s].*[^\s]$" title="Whitespace at the beginning and end are not allowed." value="<?php echo esc_url( $sp_endpoints->sp_base_url ); ?>" required <?php echo esc_attr( $disabled_due_to_license ); ?>/>
						<?php Feature_Control::end_feature_lock_container( 2 ); ?>
					</td>
				</tr>
				<tr>
					<td><b>SP EntityID / Issuer</b></td>
					<td><input type="text" name="mo_saml_sp_entity_id" placeholder="You site base URL" pattern="^[^\s].*[^\s]$" title="Whitespace at the beginning and end are not allowed." style="width: 95%;" value="<?php echo esc_attr( $sp_endpoints->sp_entity_id ); ?>" required <?php echo esc_attr( $disabled_due_to_license ); ?> /></td>
				</tr>
				<tr>
					<td>
					</td>
					<td>
						<i><b>Note:</b> If you have already shared the above URLs or Metadata with your IdP, do <b>NOT</b> change SP EntityID. It might break your existing login flow.</i>
					</td>
				</tr>
				<tr>
					<td colspan="2" style="text-align: center"><br><input type="submit" name="submit" style="width:100px;" value="Update" class="button button-primary button-large" <?php echo esc_attr( $disabled_due_to_license ); ?> /></td>
				</tr>
			</table>
		</form>
	</div>
	<br>
</div>
<div class="mo-saml-settings-container mosaml-margin-top-bottom-0-2-rem">
	<h3>Modify Organization Details in the Metadata</h3>
	<hr>
	<div class="mo-saml-settings-internal-container">
		<?php Feature_Control::start_feature_lock_container( 4 ); ?>
		<form method="post" id="mosaml_update_xml_organization_metadata_form" action="">
			<?php wp_nonce_field( 'mosaml_update_xml_organization_metadata' ); ?>
			<input type="hidden" name="option" value="mosaml_update_xml_organization_metadata" />
				<table class="mosaml-table-width">
				<tr><td><h2>Organization Details</h2></td></tr>	
					<tr>
						<td width="20%"><b>Organization Name</b></td>
						<td width="70%"><input type="text" name="mo_saml_org_name" placeholder="Enter your Organization Name" class="mo_saml_metadata_table_layout" <?php echo esc_attr( $disabled_due_to_license ); ?> value="<?php echo esc_html( $sp_organization_details->organization_name ); ?>" required/></td>
					</tr>
					<tr>
						<td><b>Organization Display Name</b></td>
						<td><input type="text" name="mo_saml_org_display_name" placeholder="Enter your Organization Display Name" class="mo_saml_metadata_table_layout" <?php echo esc_attr( $disabled_due_to_license ); ?> value="<?php echo esc_html( $sp_organization_details->organization_display_name ); ?>" required/></td>
					</tr>
					<tr>
						<td><b>Organization URL</b></td>
						<td><input type="url" name="mo_saml_org_url" placeholder="Enter your Organization URL" class="mo_saml_metadata_table_layout" <?php echo esc_attr( $disabled_due_to_license ); ?> value="<?php echo esc_html( $sp_organization_details->organization_url ); ?>" required/></td>
					</tr>
					<tr><td><h2>Technical Details</h2></td></tr>		
					<tr>
						<td><b>Technical Person Name</b></td>
						<td><input type="text" name="mo_saml_tech_name" placeholder="Enter your Technical Person Name" class="mo_saml_metadata_table_layout" <?php echo esc_attr( $disabled_due_to_license ); ?> value="<?php echo esc_html( $sp_organization_details->technical_person_name ); ?>" required/></td>
					</tr>
					<tr>
						<td><b>Technical Person Email</b></td>
						<td><input type="email" name="mo_saml_tech_email" placeholder="Enter your Technical Person Email" class="mo_saml_metadata_table_layout" <?php echo esc_attr( $disabled_due_to_license ); ?> value="<?php echo esc_html( $sp_organization_details->technical_person_email ); ?>" required/></td>
					</tr>
					<tr><td><h2>Support Details</h2></td></tr>			
					<tr>
						<td><b>Support Person Name</b></td>
						<td><input type="text" name="mo_saml_support_name" placeholder="Enter your Support Person Name" class="mo_saml_metadata_table_layout" <?php echo esc_attr( $disabled_due_to_license ); ?> value="<?php echo esc_html( $sp_organization_details->support_person_name ); ?>" required/></td>
					</tr>
					<tr>
						<td><b>Support Person Email</b></td>
						<td><input type="email" name="mo_saml_support_email" placeholder="Enter your Technical Person Name" class="mo_saml_metadata_table_layout" <?php echo esc_attr( $disabled_due_to_license ); ?> value="<?php echo esc_html( $sp_organization_details->support_person_email ); ?>" required/></td>
					</tr>
					<tr>
						<td colspan="2" style="text-align: center"><br><input type="submit" name="submit" style="width:100px;" value="Update" class="button button-primary button-large"  <?php echo esc_attr( $disabled_due_to_license ); ?>/></td>
					</tr>
				</table>
		</form>
		<?php Feature_Control::end_feature_lock_container( 4 ); ?>
	</div>
	<br>
</div>
