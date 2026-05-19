<?php
/**
 * SP Setup Template
 *
 * @package MiniOrange_SAML_20_Single_Sign_On
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\SRC\Utils\Feature_Control;
use MOSAML\SRC\Utils\Utility;

?>

<div class="mosaml-tab-content-section mosaml-margin-top-bottom-0-2-rem">
	<?php Feature_Control::check_plugin_state(); ?>
	<div class="mosaml-div-flex-row mosaml-div-flex-row-space-between">
		<div>
			<h3>List of Identity Providers</h3>
		</div>
		<div>
			<?php if ( ! empty( $disable_new_idp ) && $disable_new_idp ) : ?>
				<span class="mosaml-lock-wrapper">
					<button class="button button-primary button-large" <?php echo esc_attr( Feature_Control::get_disabled_attribute( 4 ) ); ?> <?php echo esc_attr( $disabled_due_to_license ); ?> onclick="window.location.href='<?php echo esc_url( admin_url( 'admin.php?page=mo_saml_settings&tab=sp_setup&action=upload_metadata' ) ); ?>'">Upload IDP Metadata</button>
					<?php Feature_Control::show_tooltip_for_disabled_feature( 4 ); ?>
				</span>
			<?php else : ?>
				<button class="button button-primary button-large" <?php echo esc_attr( $disabled_due_to_license ); ?> onclick="window.location.href='<?php echo esc_url( admin_url( 'admin.php?page=mo_saml_settings&tab=sp_setup&action=upload_metadata' ) ); ?>'">Upload IDP Metadata</button>
			<?php endif; ?>
		</div>
	</div>

	<div class="mosaml-idp-table-container">
		<form id="idp_form" method="post">
			<?php $idp_list_table->search_box( 'Search', 'search_idp' ); ?>
			<?php $idp_list_table->display(); ?>
		</form>
		<form id="idp_form_make_default" method="post" class="mosaml-display-none">
			<?php wp_nonce_field( 'mosaml_make_idp_default' ); ?>
			<input type="hidden" id="mosaml_idp_id_to_make_default" name="mosaml_idp_id_to_make_default" value="">
			<input type="hidden" name="option" value="mosaml_make_idp_default">
		</form>
	</div>
	<br>
	<div class="mosaml-div-flex-row mosaml-div-flex-row-end">
		<div>
			<form id="mosaml_export_configuration" method="post" class="mosaml-display-none">
				<?php wp_nonce_field( 'mosaml_export_configuration' ); ?>
				<input type="hidden" name="option" value="mosaml_export_configuration">
			</form>
			<button class="button button-primary button-large" onclick="document.getElementById('mosaml_export_configuration').submit();" >
				Export Configuration
			</button>
		</div>
		&nbsp;&nbsp;&nbsp;
		<div>
			<button class="button button-primary button-large" <?php echo ( $disable_new_idp ? esc_attr( Feature_Control::get_disabled_attribute( 4 ) ) : '' ); ?> <?php echo esc_attr( $disabled_due_to_license ); ?> onclick="window.location.href='<?php echo esc_url( admin_url( 'admin.php?page=mo_saml_settings&tab=sp_setup&action=add' ) ); ?>'">Add New IDP</button>
		</div>
	</div>
</div>

<?php
