<?php
/**
 * Admin menu page template.
 *
 * @package miniorange-saml-20-single-sign-on/template
 */
// phpcs:ignoreFile WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedVariableFound -- Template scope variables.

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\SRC\Constant\Constants;
use MOSAML\SRC\Utils\Feature_Control;

$multi_env_enabled = function_exists( 'get_option' ) ? call_user_func( 'get_option', Constants::ENABLE_MULTIPLE_ENVIRONMENTS_OPTION_NAME ) : '';

if ( Feature_Control::is_feature_locked( 4, false ) ) {
	return;
}

if ( 'checked' !== $multi_env_enabled ) {
	return;
}

if ( ! is_countable( $multiple_environment_handler ) || count( $multiple_environment_handler ) < 2 ) {
	return;
}

?>

<div class="environment_selector_internal_div environment_selector">
	<span>Selected Environment:</span>
	<select id="selectedEnv" onchange="submit_form(this)">
		<?php
			foreach ( $multiple_environment_handler as $environment ) {
				$form_id = $environment->environment_name . '_form';
				?>
				<option 
					<?php echo ( (string) $environment->selected === '1' ) ? 'selected' : ''; ?> 
					value="<?php echo esc_attr( $form_id );?>">
					<?php echo esc_html( $environment->environment_name ); ?>
				</option>
				<?php 
			}
		?>
	</select>
	<?php
		foreach ( $multiple_environment_handler as $environment ) {
			$form_id = $environment->environment_name . '_form';
			?>
			<form method="post" action="" id="<?php echo esc_attr( $form_id ); ?>">
				<?php
					if ( function_exists( 'wp_nonce_field' ) ) {
						call_user_func( 'wp_nonce_field', 'mosaml_change_environment' );
					} else {
						echo '<input type="hidden" name="_wpnonce" value="" />';
					}
				?>
				<input type="hidden" name="option" value="mosaml_change_environment"/>
				<input type="hidden" name="environment" value="<?php echo esc_html( $environment->environment_name ); ?>"/>
			</form>
			<?php
		}
	?>
</div>
