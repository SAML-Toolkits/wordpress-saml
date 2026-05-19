<?php
/**
 * Multiple Environment Menu Page Template
 *
 * @package miniorange-saml-20-single-sign-on
 */
// phpcs:ignoreFile WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedVariableFound -- Template scope variables.

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\SRC\Constant\Constants;
use MOSAML\SRC\Utils\Utility;

?>
<div class="wrap">
	<h1>
		<div style="display: flex;">
			<?php Utility::render_plugin_header(); ?>
		</div>
	</h1>
	<h2 class="nav-tab-wrapper">
		<?php
		foreach ( Constants::MULTIPLE_ENVIRONMENTS_TABS as $tab_slug => $tab_name ) :
			$active_class = $active_tab === $tab_slug ? ' nav-tab-active' : '';
			?>
			<a class="nav-tab<?php echo esc_attr( $active_class ); ?>" href="<?php echo esc_url( 'admin.php?page=mosaml-multiple-environment&tab=' . $tab_slug ); ?>"><?php echo esc_html( $tab_name ); ?></a>
		<?php endforeach; ?>
	</h2>

	<div class="mosaml-div-flex mosaml-div-width-auto">
		<div class="mosaml-width-70">
			<?php $template_handler->render_ui(); ?>
		</div>
		<div class="mosaml-width-30">
			<?php $sidebar_ui_handler->render_ui(); ?>
		</div>
	</div>
</div>
