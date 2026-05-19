<?php
/**
 * Addons UI Handler.
 *
 * @package miniorange-saml-20-single-sign-on
 */

namespace MOSAML\SRC\Handler\UI;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\SRC\Interfaces\Tab_UI_Handler_Interface;
use MOSAML\SRC\Utils\Utility;

/**
 * Class Addons_UI_Handler
 *
 * Handles the rendering of the Addons tab UI.
 */
class Addons_UI_Handler implements Tab_UI_Handler_Interface {

	/**
	 * Render the UI.
	 *
	 * @return void
	 */
	public function render_ui() {
		?>
		<div class="mosaml-tab-content-section mosaml-margin-top-bottom-0-2-rem">
			<?php Utility::handle_license_calls( 'fetch_addons_view', 'library', '' ); ?>
		</div>
		<?php
	}
}
