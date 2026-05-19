<?php
/**
 * SSO Redirection Settings Main Template.
 *
 * @package miniorange-saml-20-single-sign-on
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

?>

<div class="mo-saml-nav-subtab-div mo-saml-redirection-sso-div">
	<a class="mo-saml-nav-subtab mo-saml-redirection-settings-nav-subtab mosaml-text-decoration-none <?php echo( 'settings' === $active_tab ? 'mo-saml-nav-subtab-active' : '' ); ?>"
		href="
		<?php
		echo isset( $_SERVER['REQUEST_URI'] ) ? esc_url(
			add_query_arg(
				array(
					'subtab' => 'settings',
					'tab'    => 'sso_redirection_settings',
				),
				esc_url_raw( wp_unslash( $_SERVER['REQUEST_URI'] ) )
			)
		) : '';
		?>
		">
		SSO Redirection Settings
	</a>
	<a class="mo-saml-nav-subtab mo-saml-redirection-settings-nav-subtab mosaml-text-decoration-none <?php echo( 'sso_links' === $active_tab ? 'mo-saml-nav-subtab-active' : '' ); ?>"
		href="
		<?php
		echo isset( $_SERVER['REQUEST_URI'] ) ? esc_url(
			add_query_arg(
				array(
					'subtab' => 'sso_links',
					'tab'    => 'sso_redirection_settings',
				),
				esc_url_raw( wp_unslash( $_SERVER['REQUEST_URI'] ) )
			)
		) : '';
		?>
		">
		SSO Links and Button
	</a>
</div>
