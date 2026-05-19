<?php
/**
 * This file contains the HTML code for the Manage certificate tab.
 *
 * @package MOSAML
 * @subpackage MOSAML/src/template
 */
// phpcs:ignoreFile WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedVariableFound -- Template scope variables.

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\SRC\Utils\Utility;
use MOSAML\SRC\Utils\Feature_Control;
use MOSAML\SRC\Constant\Constants;

?>

<div class="mosaml-tab-content-section mosaml-margin-top-bottom-0-2-rem">
	<?php Feature_Control::check_plugin_state(); ?>
	<table class="mosaml-width-100 mosaml-table-border-collapse">
		<tr>
			<td colspan="2">
				<h3>Certificate Details</h3>
				<hr style="margin-bottom:20px;">
			</td>
		</tr>
		<tr style="text-align:center;">
			<td style="font-weight:bold;border:1px solid #949090;padding:2%; width:50%;">Certificate Thumbprint</td>
			<td style="border:1px solid #949090;padding:2%; width:50%;"><?php echo esc_attr( $thumbprint ); ?></td>
		</tr>
		<tr style="text-align:center;">
			<td style="font-weight:bold; border:1px solid #949090;padding:2%; width:50%;">Expiry Date</td>
			<td style="border:1px solid #949090;padding:2%; width:50%;"><?php echo esc_attr( $valid_to ); ?></td>
		</tr>
		<tr style="text-align:center;">
			<td style="font-weight:bold; border:1px solid #949090;padding:2%; width:50%;">Service Provider Certificate</td>
			<td style="border:1px solid #949090;padding:2%; width:50%;">
				<?php Feature_Control::start_feature_lock_container( 2 ); ?>
				<input type="button" class="button button-primary button-large" value="Download" onclick="document.forms['mo_saml_download'].submit()" <?php echo esc_attr( $disabled_due_to_license ); ?>/>
				<?php Feature_Control::end_feature_lock_container( 2 ); ?>
			</td>
		</tr>
		<?php if ( $custom_certificate_data->is_custom_certificate ) : ?>
			<tr style="text-align:center;">
				<td style="font-weight:bold;border:1px solid #949090;padding:2%; width:50%;">Custom Certificate</td>
				<td style="border:1px solid #949090;padding:2%; width:50%;">True</td>
			</tr>
		<?php endif; ?>
		<tr>
			<td colspan="2">
				<div>
					<?php
					if ( $remaining_days_for_db_certificate < 60 && $remaining_days_for_db_certificate > 0 ) {
						echo '<p style="font-size: medium;background-color:#CBCBCB;padding:2%;"><b>Plugin\'s current certificates will expire in <span style = "color: red" >' . esc_attr( $remaining_days_for_db_certificate ) . '</span> days. Please upgrade immediately below.</b></p>';
					} elseif ( $remaining_days_for_db_certificate < 0 ) {
						echo '<p style="font-size: medium;background-color:#CBCBCB;padding:2%;"><b>Plugin\'s current certificates have already expired . Please Upgrade immediately below .</b ></p > ';
					}
					?>
				</div>
			</td>
		</tr>
		<tr>
			<td><br></td>
		</tr>
	</table>
</div>

<div class="mo-saml-nav-subtab-div mosaml-border-bottom">
	<div id="mosaml_miniorange_certificate" class="mo-saml-nav-subtab mo-saml-redirection-settings-nav-subtab mosaml-text-decoration-none <?php echo esc_attr( $custom_certificate_data->is_custom_certificate ? '' : 'mo-saml-nav-subtab-active' ); ?> mo_saml_description" onclick="clickHandle(event, 'miniorange_certificate')">
		miniOrange Default Certificate Configuration
	</div> 
	<div id="mosaml_custom_certificate" class="mo-saml-nav-subtab mo-saml-redirection-settings-nav-subtab mosaml-text-decoration-none <?php echo esc_attr( $custom_certificate_data->is_custom_certificate ? 'mo-saml-nav-subtab-active' : '' ); ?> mo_saml_description" onclick="clickHandle(event, 'custom_certificate')">
		Use Custom Certificate
	</div>
</div>

<div id="miniorange_certificate" class="tabcontent" style="background:white;display: <?php echo esc_attr( $style_value ); ?>">
	<?php if ( $remaining_days_certificate_file < 60 && $remaining_days_for_db_certificate < 60 ) { ?>
		<table class="mo_saml_certificate_expiry_message_display_table">
			<tr class="mo_saml_certificate_expiry_message_display_warning">
			<td colspan="3">
				<h4 class="mo-saml-cert-expiry-notice">
				You are currently using an older version of the miniOrange SAML SSO plugin which does not have the latest certificate.</br></br>
				<b>Please follow the <a href="<?php echo Constants::UPGRADE_FAQ; ?>" target="_blank" class="mo-saml-link-color">steps here</a> to update your plugin and get the latest certificates.</b></h4>
            </td>
			</tr>
		</table>
	<?php } elseif ( $disable_upgrade_tab ) { ?>
		<table class="mo-saml-cert-steps-table" style="display: <?php echo esc_attr( isset( $display_upgrade_certificate_steps ) ? $display_upgrade_certificate_steps : 'block' ); ?>">
			<tr>
				<td colspan="4">
					<h4 class="mosaml-cert-steps-title">Follow the steps mentioned below for successful migration of new certificates:</h4>
				</td>
			</tr>
			<tr>
				<td colspan="4">
					<div>
						<p class="mosaml-cert-step-intro">
							<div>
								<b>Step 1: Provide this plugin information to your Identity Provider team. You can choose one of the below options</b>
							</div>
						</p>
					</div>
				</td>
			</tr>
			<tr>
				<td colspan="4" class="mosaml-cert-label-cell-indent">
					a) Download the Plugin XML metadata and upload it on your Identity Provider
				</td>
				<td class="mosaml-cert-action-cell">
					<input type="button" class="button button-primary button-large" value="Download Metadata" onclick="document.getElementById('mosaml_download_new_metadata').submit();" />
				</td>
			</tr>
			<tr>
				<td colspan="4" class="mosaml-cert-or-cell">OR</td>
			</tr>
			<tr>
				<td colspan="4" class="mosaml-cert-label-cell-indent">
					b) Download the New Plugin Certificate and upload it on your Identity Provider
				</td>
				<td class="mosaml-cert-action-cell">
					<input type="button" class="button button-primary button-large" onclick="document.forms['mosaml_download_new_cert'].submit()" value="Download Certificate" />
				</td>
			</tr>
			<tr>
				<td><br/></td>
			</tr>
			<tr>
				<td colspan="4" class="mosaml-cert-label-cell">
					<b>Step 2: Select the IDP for which you want to apply the certificate:</b>
				</td>
				<td class="mosaml-cert-action-cell">
					<select name="mosaml_cert_idp_name" id="mosaml_cert_idp_name">
						<option value="All IDPs">Apply to All IDPs</option>
						<?php
						foreach ( $identity_providers as $idp_details ) {
							?>
							<option value="<?php echo esc_attr( $idp_details->idp_id ); ?>"><?php echo esc_attr( $idp_details->idp_name ); ?></option>
						<?php } ?>
					</select>
				</td>
			</tr>
			<tr>
				<td><br/></td>
			</tr>

			<?php if ( $cert_idp_name != 'DEFAULT' ) { ?>
				<tr>
					<td colspan="4" class="mosaml-cert-label-cell">
						<b>Step 3: Test if the Certficate have been added to IDP</b>
					</td>
					<td class="mosaml-cert-action-cell">
						<input type="button" name="test" onclick="showTestWindow('<?php echo esc_url( Utility::get_test_config_url( $cert_idp_name, true ) ); ?>');" value="Test Connection" class="button button-primary button-large" />
					</td>
				</tr>
				<tr>
					<td><br/></td>
				</tr>
				<tr>
					<td colspan="4" class="mosaml-cert-label-cell">
						<div>
							<b>Step 4:</b>
							<b>You're all set click on Upgrade to miniOrange to apply latest certificates</b>
						</div>
					</td>
			<?php } else { ?>
				<tr>
					<td colspan="4" class="mosaml-cert-label-cell">
						<div>
							<b>Step 3:</b>
							<b>Once all your IDPs have added the new certificate at their end, you're ready to apply the latest certificate</b>
						</div>
					</td>
			<?php } ?>
				<td class="mosaml-cert-action-cell">
					<button type="button" class="button button-primary button-large" data-toggle="modal" id="upgrade_to_miniorange_certs" data-target="#upgrade-cert-modal" onclick="applyLatestCertificate()">Apply Certificate</button>
				</td>
			</tr>
			<tr>
				<td><br></td>
			</tr>
		</table>
	<?php } else { ?>
		<table class="mo_saml_certificate_expiry_message_display_table">
			<tr class="mo_saml_certificate_expiry_message_display">
				<td>
					<b>Your certificates are upto date.</b>
				</td>
			</tr>
		</table>
	<?php } ?>
</div>

<div id="custom_certificate" class="tabcontent" style="background: white;display: <?php echo esc_attr( $enable_custom_certificate_display ); ?>">
	<form method="post">
		<div>
			<h3>Add Custom Certificate</h3>
			[&nbsp;<a href="https://developers.miniorange.com/docs/saml/wordpress/Custom-Certificate" target="_blank">Click here</a> to know how this is useful. ]
		</div>
		<div class="mosaml-custom-certificate-container">
			<br><hr>
			<?php Feature_Control::start_feature_lock_container( 3 ); ?>
			<div class="mosaml-custom-certificate-table">
			<div class="mosaml-custom-certificate-row">
				<div class="mosaml-custom-certificate-label-cell">
					<?php wp_nonce_field( 'mosaml_add_custom_certificate' ); ?>
					<input type="hidden" name="option" value="mosaml_add_custom_certificate" />
					<strong>X.509 Public Certificate <span class="mosaml-custom-certificate-required">*</span>:</strong>
				</div>
				<div class="mosaml-custom-certificate-input-cell" colspan="2">
					<textarea rows="6" cols="5" name="saml_public_x509_certificate" placeholder="Enter the X.509 Public Certificate here" class="mosaml-custom-certificate-textarea" required><?php echo esc_attr( $public_cert ); ?></textarea>
				</div>
			</div>
			<div class="mosaml-custom-certificate-row">
				<div class="mosaml-custom-certificate-cell"></div>
				<div class="mosaml-custom-certificate-cell">
					<b>NOTE:</b> Format of the certificate:<br/>
					<b>-----BEGIN CERTIFICATE-----<br/>XXXXXXXXXXXXXXXXXXXXXXXXXXX<br/>-----END CERTIFICATE-----</b>
				</div>
			</div>
			<div class="mosaml-custom-certificate-row">
				<div class="mosaml-custom-certificate-label-cell"><strong>X.509 Private Certificate <span class="mosaml-custom-certificate-required">*</span>:</strong></div>
				<div class="mosaml-custom-certificate-input-cell-no-padding" colspan="2">
					<textarea rows="6" cols="5" name="saml_private_x509_certificate" placeholder="Enter the X.509 Private Certificate here" class="mosaml-custom-certificate-textarea" required><?php echo esc_attr( $private_cert ); ?></textarea>
				</div>
			</div>
			<div class="mosaml-custom-certificate-row">
				<div class="mosaml-custom-certificate-cell">&nbsp;</div>
				<div class="mosaml-custom-certificate-cell">
					<b>NOTE:</b> Format of the certificate:<br/>
					<b>-----BEGIN PRIVATE KEY-----<br/>XXXXXXXXXXXXXXXXXXXXXXXXXXX<br/>-----END PRIVATE KEY-----</b>
				</div>
			</div>
			<div id="save_config_element" class="mosaml-custom-certificate-row">
				<div class="mosaml-custom-certificate-cell">&nbsp;</div>
				<div class="mosaml-custom-certificate-cell">
					<br />
					<input class="button button-primary button-large mosaml-custom-certificate-upload-btn" id="upload_certificate_modal" value="Upload" name="submit" type="submit" />
					<?php
					if ( $private_cert == '' && $public_cert == '' ) {
						echo '<input disabled type="submit" name="submit" value="Reset" class="button button-primary button-large mosaml-custom-certificate-reset-btn" />';
					} else {
						echo '<input type="submit" name="submit" value="Reset" class="button button-primary button-large mosaml-custom-certificate-reset-btn" />';
					}
					?>
				</div>
			</div>
			</div>
			<?php Feature_Control::end_feature_lock_container( 3 ); ?>
		</div>
	</form>
</div>

<form method="post" action="" name="mosaml_download_new_cert">
	<?php wp_nonce_field( 'mosaml_download_new_cert' ); ?>
	<input type="hidden" name="option" value="mosaml_download_new_cert" />
</form>
<form method="post" action="" id="mosaml_download_new_metadata">
	<?php wp_nonce_field( 'mosaml_download_new_metadata' ); ?>
	<input type="hidden" name="option" value="mosaml_download_new_metadata"/>
</form>
<form method="post" name="mosaml_upgrade_new_certificate" id="mosaml_upgrade_new_certificate_form">
	<?php wp_nonce_field( 'mosaml_upgrade_new_certificate' ); ?>
	<input type="hidden" name="option" value="mosaml_upgrade_new_certificate"/>
	<input type="hidden" name="selected_idp_id" value="">
</form>
<form method="post" action="" name="mo_saml_download">
	<?php wp_nonce_field( 'mosaml_download_cert' ); ?>
	<input type="hidden" name="option" value="mosaml_download_cert" />
</form>
<div class="modal" id="upgrade-cert-modal" role="dialog" style="margin-top: 200px;">
	<div class="modal-dialog">
		<div class="modal-content">
			<div class="modal-header">
				<button type="button" class="close" data-dismiss="modal">&times;</button>
				<h2 class="modal-title" style="font-size: 20px;">Are you sure you want to Upgrade?</h2>
			</div>
			<div class="modal-footer" style="text-align:center; border-top:0px;">
				<button style="margin-right: 15px;padding:0px 30px;" type="button" class="button button-primary button-large" value="upgrade_cert" id="upgrade_cert" onclick="document.getElementById('upgrade_cert_form').submit();">
					Confirm Upgrade
				</button>
				<button style="padding:0px 30px;" type="button" class="button button-primary button-large" data-dismiss="modal">Don't Upgrade</button>
			</div>
		</div>
	</div>
</div>
