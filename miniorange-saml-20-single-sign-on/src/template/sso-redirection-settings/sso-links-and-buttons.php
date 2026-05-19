<?php
/**
 * SSO Redirection Settings Main Template.
 *
 * @package miniorange-saml-20-single-sign-on
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\SRC\Constant\Plugin_Files_Constants;
use MOSAML\SRC\Utils\Feature_Control;
use MOSAML\SRC\Constant\Constants;

?>

<div class="mo-saml-redirection-sso-div mo-saml-outer-div-padding" id="mo-saml-redirection-outer-div">
	<p>[&nbsp;<a href="<?php echo esc_url( Constants::SSO_LINKS_DOC_URL ); ?>" target="_blank">Click here</a> to know how this is useful. ]</p>
	<?php Feature_Control::check_plugin_state(); ?>
	<?php
		require_once Plugin_Files_Constants::TEMPLATE_SSO_LINKS;
		require_once Plugin_Files_Constants::TEMPLATE_SSO_BUTTON;
		require_once Plugin_Files_Constants::TEMPLATE_SHORTCODE_WIDGET_SETTINGS;
	?>
</div>
