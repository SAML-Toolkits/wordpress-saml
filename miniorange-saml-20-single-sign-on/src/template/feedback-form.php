<?php
/**
 * Feedback Form Template.
 *
 * @package miniorange-saml-20-single-sign-on
 */
// phpcs:ignoreFile WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedVariableFound -- Template scope variables.

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\SRC\Handler\UI\Feedback_Form_Handler;

$plugin_dir_url = Feedback_Form_Handler::get_plugin_dir_url();

$user  = wp_get_current_user();
$email = $user->user_email;
?>
<div id="mo_saml_feedback_modal" class="mo_modal" style="display: none;">
	<div class="mo_modal-content" style="width:50%">
		<h3 style="margin: 2%; text-align:center;">
			<b><?php esc_html_e( 'Your feedback', 'miniorange-saml-20-single-sign-on' ); ?></b>
			<span class="mo_saml_close" style="cursor: pointer">&times;</span>
		</h3>
		<hr style="width:75%;">
		<form name="f" method="post" action="" id="mosaml_feedback">
			<?php wp_nonce_field( 'mosaml_feedback' ); ?>
			<input type="hidden" name="option" value="mosaml_feedback"/>
			<div>
				<p style="margin:2%">
				<h4 style="margin: 2%; text-align:center;"><?php esc_html_e( 'Please help us to improve our plugin by giving your opinion.', 'miniorange-saml-20-single-sign-on' ); ?><br></h4>
				<div id="smi_rate" style="text-align:center">
					<input type="radio" name="rate" class="mo-saml-fb-radio" id="angry" value="1" />
					<label for="angry">
						<img class="sm" src="<?php echo esc_url( $plugin_dir_url . '/static/image/angry.webp' ); ?>" alt="Angry" />
					</label>

					<input type="radio" name="rate" class="mo-saml-fb-radio" id="sad" value="2" />
					<label for="sad">
						<img class="sm" src="<?php echo esc_url( $plugin_dir_url . '/static/image/sad.webp' ); ?>" alt="Sad" />
					</label>

					<input type="radio" name="rate" class="mo-saml-fb-radio" id="neutral" value="3" />
					<label for="neutral">
						<img class="sm" src="<?php echo esc_url( $plugin_dir_url . '/static/image/normal.webp' ); ?>" alt="Neutral" />
					</label>

					<input type="radio" name="rate" class="mo-saml-fb-radio" id="smile" value="4" />
					<label for="smile">
						<img class="sm" src="<?php echo esc_url( $plugin_dir_url . '/static/image/smile.webp' ); ?>" alt="Smile" />
					</label>

					<input type="radio" name="rate" class="mo-saml-fb-radio" id="happy" value="5" checked />
					<label for="happy">
						<img class="sm" src="<?php echo esc_url( $plugin_dir_url . '/static/image/happy.webp' ); ?>" alt="Happy" />
					</label>
				</div><br>
				<div id="outer">
						<span id="result"><?php esc_html_e( 'Thank you for appreciating our work', 'miniorange-saml-20-single-sign-on' ); ?></span>
					</div>
				<hr style="width:75%;">
				<div class="radio-email" style="text-align:center;">
					<div class="mo_saml_feedback_email" style="display:inline-block; width:60%;">
						<input type="email" id="query_mail" name="query_mail" placeholder="<?php esc_attr_e( 'Please enter your email address', 'miniorange-saml-20-single-sign-on' ); ?>" required value="<?php echo esc_attr( $email ); ?>" readonly="readonly" />
						<input type="radio" name="edit" class="mo-saml-fb-radio" id="edit" onclick="editName()" value="" />
						<label for="edit"><img class="editable" src="<?php echo esc_url( $plugin_dir_url . '/static/image/edit-icon.webp' ); ?>" /></label>
					</div>
					<br><br>
					<textarea id="query_feedback" name="query_feedback" rows="4" style="width: 60%" placeholder="<?php esc_attr_e( 'Tell us what happened!', 'miniorange-saml-20-single-sign-on' ); ?>"></textarea>
					<br><br>
					<input type="checkbox" name="get_reply" value="reply" checked />
					<?php esc_html_e( 'miniOrange representative will reach out to you at the email-address entered above.', 'miniorange-saml-20-single-sign-on' ); ?>
				</div>
				<br>
				<div class="mo-modal-footer" style="text-align: center;margin-bottom: 2%">
					<input type="submit" name="miniorange_feedback_submit" class="button button-primary button-large" value="<?php esc_attr_e( 'Send', 'miniorange-saml-20-single-sign-on' ); ?>" />
					<span width="30%">&nbsp;&nbsp;</span>
					<input type="button" name="miniorange_skip_feedback" class="button button-primary button-large mosaml-skip-feedback" value="<?php esc_attr_e( 'Skip', 'miniorange-saml-20-single-sign-on' ); ?>" />
				</div>
			</div>
		</form>
		<form name="f" method="post" action="" id="mo_saml_feedback_form_close">
			<?php wp_nonce_field( 'mosaml_skip_feedback' ); ?>
			<input type="hidden" name="option" value="mosaml_skip_feedback" />
		</form>
	</div>
</div>

