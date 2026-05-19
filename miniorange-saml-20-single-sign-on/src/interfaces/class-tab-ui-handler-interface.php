<?php
/**
 * Tab UI handler interface.
 *
 * @package miniorange-saml-20-single-sign-on
 */

namespace MOSAML\SRC\Interfaces;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Base Template Handler.
 */
interface Tab_UI_Handler_Interface {

	/**
	 * Render the UI.
	 *
	 * @return void
	 */
	public function render_ui();
}
