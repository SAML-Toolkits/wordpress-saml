<?php
// phpcs:ignoreFile WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedVariableFound -- Template scope variables.

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\SRC\Constant\Constants;

$bulk_action_record_count = is_countable( $bulk_action_record ) ? count( $bulk_action_record ) : 0;
$idp_details_count        = is_countable( $idp_details ) ? count( $idp_details ) : 0;
$render_selected_idp_names = static function () use ( $bulk_action_record, $idp_details ) {
	?>
	<ul class="mosaml-list-style-disc">
		<?php foreach ( $bulk_action_record as $idp_id ) : ?>
			<?php
			$idp_name = '';
			foreach ( $idp_details as $item ) {
				if ( $item->idp_id === $idp_id ) {
					$idp_name = $item->idp_name;
					break;
				}
			}
			?>
			<li><?php echo esc_html( ! empty( $idp_name ) ? $idp_name : $idp_id ); ?></li>
		<?php endforeach; ?>
	</ul>
	<?php
};

?>
<div class="mosaml-tab-content-section mosaml-margin-top-bottom-0-2-rem">
	<form method="post" name="mosaml_bulk_action_submit_<?php echo esc_attr( $request_action ); ?>">
		<?php wp_nonce_field( 'mosaml_bulk_action_confirmation' ); ?>
		<input type="hidden" name="option" value="mosaml_bulk_action_confirmation">
		<input type="hidden" name="bulk_action" value="<?php echo esc_attr( $request_action ); ?>">

		<?php foreach ( $bulk_action_record as $record ) : ?>
			<input type="hidden" name="bulk_action_record[]" value="<?php echo esc_attr( $record ); ?>">
		<?php endforeach; ?>

		<h3>
			<?php
			if ( 'delete' === $request_action ) {
				echo esc_html__( 'Delete Identity Provider', 'miniorange-saml-20-single-sign-on' );
			} else {
				echo esc_html( Constants::IDP_BULK_ACTIONS[ $request_action ] ) . ' ' . esc_html__( 'Identity Providers', 'miniorange-saml-20-single-sign-on' );
			}
			?>
		</h3>

		<?php if ( in_array( $default_idp_id, $bulk_action_record, true ) && 'inactive' === $request_action ) : ?>
			<?php if ( 1 === $idp_count || $bulk_action_record_count === $idp_count ) : ?>
				<?php $show_confirm_button = false; ?>
				<p>You are trying to <b><?php echo esc_html( Constants::IDP_BULK_ACTIONS[ $request_action ] ); ?></b> the default IDP. Default IDP cannot be deactivated.</p>
			<?php else : ?>
				<?php $disabled = 'disabled'; ?>
				<p>You are trying to <b><?php echo esc_html( Constants::IDP_BULK_ACTIONS[ $request_action ] ); ?></b> the default IDP. You should keep at least one IDP as default. Please select another IDP to make it default. If the newly selected IDP is not active, it will be activated automatically.</p>
				<select class="mosaml-min-width-20" name="bulk_action_default_idp_id">
					<option value="">Select Default IDP</option>
					<?php foreach ( $idp_details as $idp ) : ?>
						<?php
						if ( in_array( $idp->idp_id, $bulk_action_record, true ) ) {
							continue;
						}
						?>
						<option value="<?php echo esc_attr( $idp->idp_id ); ?>">
						<?php
						echo esc_html( $idp->idp_name );
						if ( 'inactive' === $idp->status ) {
							echo esc_html__( ' (Currently Deactivated)', 'miniorange-saml-20-single-sign-on' ); }
						?>
						</option>
					<?php endforeach; ?>
				</select>
				<?php $submit_button_text = 'Save & ' . Constants::IDP_BULK_ACTIONS[ $request_action ]; ?>
				<br><br>
			<?php endif; ?>
		<?php elseif ( in_array( $default_idp_id, $bulk_action_record, true ) && 'delete' === $request_action && 0 < ( $idp_details_count - $bulk_action_record_count ) ) : ?>
			<?php $disabled = 'disabled'; ?>
			<p>You are trying to <b><?php echo esc_html( Constants::IDP_BULK_ACTIONS[ $request_action ] ); ?></b> the default IDP. Please select another IDP from the dropdown below to make it default before proceeding further. If the newly selected IDP is not active, it will be activated automatically.</p>
			<select class="mosaml-min-width-20" name="bulk_action_default_idp_id">
				<option value="">Select Default IDP</option>
				<?php foreach ( $idp_details as $idp ) : ?>
					<?php
					if ( in_array( $idp->idp_id, $bulk_action_record, true ) ) {
						continue;
					}
					?>
					<option value="<?php echo esc_attr( $idp->idp_id ); ?>">
					<?php
					echo esc_html( $idp->idp_name );
					if ( 'inactive' === $idp->status ) {
						echo esc_html__( ' (Currently Deactivated)', 'miniorange-saml-20-single-sign-on' ); }
					?>
					</option>
				<?php endforeach; ?>
			</select>
			<?php $submit_button_text = 'Save & ' . Constants::IDP_BULK_ACTIONS[ $request_action ]; ?>
			<br>
			<br>
			<p><?php echo esc_html__( 'Your IDP configuration will be deleted forever. Are you sure you want to delete IDP configurations for:', 'miniorange-saml-20-single-sign-on' ); ?></p>
			<?php $render_selected_idp_names(); ?>
			<p>
				<b><?php echo esc_html__( 'Note:', 'miniorange-saml-20-single-sign-on' ); ?></b>
				<?php echo esc_html__( 'Along with IDP configurations this action will also delete all Attribute/Role Mapping and Redirection & SSO settings. If you only wish to update the IDP configuration, please do it using the Edit Configurations option provided in the dropdown.', 'miniorange-saml-20-single-sign-on' ); ?>
			</p>
		<?php else : ?>
			<?php if ( 'delete' === $request_action ) : ?>
				<p><?php echo esc_html__( 'Your IDP configurations will be deleted forever. Are you sure you want to delete IDP configurations for:', 'miniorange-saml-20-single-sign-on' ); ?></p>
				<?php $render_selected_idp_names(); ?>
				<p>
					<b><?php echo esc_html__( 'Note:', 'miniorange-saml-20-single-sign-on' ); ?></b>
					<?php echo esc_html__( 'Along with IDP configurations this action will also delete all Attribute/Role Mapping and Redirection & SSO settings. If you only wish to update the IDP configuration, please do it using the Edit Configurations option provided in the dropdown.', 'miniorange-saml-20-single-sign-on' ); ?>
				</p>
			<?php else : ?>
				<p>Are you sure want to <b><?php echo esc_html( Constants::IDP_BULK_ACTIONS[ $request_action ] ); ?></b> the following IDPs?</p>
				<?php $render_selected_idp_names(); ?>
			<?php endif; ?>
		<?php endif; ?>
		<p>
			<?php if ( $show_confirm_button ) : ?>
				<input type="submit" id="mosaml_bulk_action_submit" value="<?php echo esc_attr( $submit_button_text ); ?>" class="button button-large button-primary" <?php echo esc_attr( $disabled ); ?>>
			<?php endif; ?>
			<input type="button" value="Cancel" class="button button-large button-secondary" onclick="window.location.href='<?php echo esc_url( admin_url( 'admin.php?page=mo_saml_settings&tab=sp_setup' ) ); ?>';">
		</p>
	</form>
</div>
