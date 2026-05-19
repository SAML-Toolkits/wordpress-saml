<?php
/**
 * License expiry page template.
 *
 * @package miniorange-saml-20-single-sign-on/template
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

?>

<div class="mosaml-grace-notice-flex mosaml-grace-notice-overlay">
	<div class="mosaml-grace-notice-flex-column mosaml-grace-notice-content">
		<div>
			<h2>IMPORTANT : License Expired!!</h2>
			<div class="mosaml-grace-notice-flex">
				<img width="50" height="50" src="<?php echo esc_url_raw( $mo_logo_url ); ?>" alt="miniOrange Logo" class="mosaml-grace-notice-logo">
				<h3>miniOrange SAML Single Sign-On Plugin</h3>
			</div>
		</div>
		<div class="mosaml-grace-notice-list">
			<ul>
				<li>Your plugin license has expired and is currently in grace period for renewal.</li>
				<li>The SSO will STOP working completely for all users including Administrators once the grace period is over.</li>
			</ul>
		</div>
		<div class="mosaml-grace-notice-flex mosaml-grace-notice-btn-div">
			<button id="mosaml_grace_notice_faq_btn" class="mosaml-grace-notice-success-btn mosaml-grace-notice-btns">How to Renew?</button>
			<?php
			if ( ! $license_status['STATUS'] && 'LICENSE_IN_GRACE' === $license_status['CODE'] ) {
				?>
				<button id="mosaml_grace_notice_cancel_btn" class="mosaml-grace-notice-error-btn mosaml-grace-notice-btns">I Accept the Risk</button>
				<?php
			} elseif ( $license_status['STATUS'] ) {
				?>
				<button id="mosaml_grace_notice_deactivate_btn" class="mosaml-grace-notice-error-btn mosaml-grace-notice-btns">Deactivate Plugin</button>
				<?php
			}
			?>
		</div>
		<button id="mosaml_grace_notice_sync_license_btn" class="mosaml-plain-notice-btn">Renewed Already? Click here</button>
		<p>Please reach out to us at <a href="mailto:samlsupport@xecurify.com">samlsupport@xecurify.com</a> in case of any issues.</p>
	</div>
</div>
