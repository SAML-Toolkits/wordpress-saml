<?php
/**
 * Attribute Dropdown Component Template
 *
 * This component renders an attribute dropdown or input field based on available test configuration.
 * If test configuration attributes are available, it shows a dropdown. Otherwise, it shows a text input.
 *
 * Expected variables:
 * - $field_name: The base name for the form field (e.g., 'username', 'email')
 * - $field_label: The display label for the field
 * - $current_value: The current selected/entered value
 * - $test_attributes: Array of available test configuration attributes
 * - $is_required: Boolean indicating if the field is required
 * - $placeholder: Placeholder text for the input field
 *
 * @package MOSAML
 * @since 1.0.0
 */
// phpcs:ignoreFile WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedVariableFound -- Template scope variables.

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

$is_required       = isset( $is_required ) ? $is_required : false;
$placeholder       = "Enter attribute name for {$field_label}";
$test_attributes   = isset( $test_attributes ) && is_array( $test_attributes ) ? $test_attributes : array();
$current_value     = isset( $current_value ) ? $current_value : '';
$width_class       = isset( $width_class ) ? $width_class : 'mo-saml-attr-input-width';
$field_name_attr   = "mo_saml_{$field_name}";
$field_id_name     = isset( $field_id_name ) ? $field_id_name : '';
$disabled_in_field = isset( $disabled ) ? $disabled : false;
?>

<?php if ( ! empty( $test_attributes ) ) : ?>
	<select name="<?php echo esc_attr( $field_name_attr ); ?>" 
			id="<?php echo esc_attr( $field_id_name ); ?>"
			class="<?php echo esc_attr( $width_class ); ?>" 
			<?php disabled( $disabled_in_field ); ?>
			<?php echo $is_required ? 'required=""' : ''; ?>>
		<option value="">-- Select <?php echo esc_html( $field_label ); ?> Attribute --</option>
		<?php foreach ( $test_attributes as $attr_name ) : ?>
			<option value="<?php echo esc_attr( $attr_name ); ?>" <?php selected( $current_value, $attr_name ); ?>>
				<?php echo esc_html( $attr_name ); ?>
			</option>
		<?php endforeach; ?>
	</select>
<?php else : ?>
	<input type="text" 
			name="<?php echo esc_attr( $field_name_attr ); ?>" 
			placeholder="<?php echo esc_attr( $placeholder ); ?>" 
			class="<?php echo esc_attr( $width_class ); ?>" 
			value="<?php echo esc_attr( $current_value ); ?>" 
			id="<?php echo esc_attr( $field_id_name ); ?>" 
			<?php disabled( $disabled_in_field ); ?>
			<?php echo $is_required ? ' required=""' : ''; ?>>
<?php endif; ?>
