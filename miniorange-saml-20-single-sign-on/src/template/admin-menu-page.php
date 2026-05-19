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
use MOSAML\SRC\Constant\Plugin_Files_Constants;
use MOSAML\SRC\Utils\Utility;

?>
<div class="wrap">
	<h1>
		<div style="display: flex;">
			<?php Utility::render_plugin_header(); ?>
			<?php if( 'account_settings' !== $active_tab && 'addons' !== $active_tab ) { require_once Plugin_Files_Constants::TEMPLATE_SELECTED_ENVIRONMENT; } ?>
			
		</div>
	</h1>
	<?php if ( ! empty( $certificate_expired ) ) : ?>
					<?php require_once Plugin_Files_Constants::CERTIFICATE_EXPIRED_SECURITY_ALERT; ?>
	<?php endif; ?>
	<?php if ( 'completed' === $db_update_status ) : ?>
		<h2 class="nav-tab-wrapper mosaml-nav-tab-row">
			<?php
			foreach ( Constants::TABS as $tab_slug => $tab_name ) :
				$active_class = $active_tab === $tab_slug ? ' nav-tab-active' : '';
				?>
				<a class="nav-tab<?php echo esc_attr( $active_class ); ?>" href="<?php echo esc_url( 'admin.php?page=mo_saml_settings&tab=' . $tab_slug ); ?>"><?php echo esc_html( $tab_name ); ?></a>
			<?php endforeach; ?>
		</h2>
	<?php endif; ?>

	<div class="mosaml-div-flex mosaml-div-width-auto">
		<div class="mosaml-width-70">
			<?php if ( 'completed' === $db_update_status ) : ?>
				<?php $template_handler->render_ui(); ?>
			<?php else : ?>
				<?php require_once Plugin_Files_Constants::TEMPLATE_DATABASE_UPDATE_REQUIRED; ?>
			<?php endif; ?>
		</div>
		<div class="mosaml-width-30">
			<?php $sidebar_ui_handler->render_ui(); ?>
		</div>
	</div>
</div>
