<?php
/**
 * SP Setup Handler.
 *
 * @package miniorange-saml-20-single-sign-on/module/standard/handler/admin
 */

namespace MOSAML\Module\Standard\Handler\Admin;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\Module\Base\Handler\Admin\SP_Setup_Data_Handler as Base_SP_Setup_Data_Handler;
use MOSAML\SRC\Interfaces\Form_Data_Handler_Interface;
use MOSAML\SRC\Utils\Utility;

/**
 * SP Setup Handler.
 */
class SP_Setup_Data_Handler extends Base_SP_Setup_Data_Handler implements Form_Data_Handler_Interface {

	/**
	 * Apply version-specific settings to the data object.
	 * Standard version specific settings.
	 *
	 * @return void
	 */
	public function validate_and_save_data() {
		$upload_metadata = Utility::sanitize_post_data( 'upload_metadata' );

		if ( 'url' === $upload_metadata || 'file' === $upload_metadata ) {
			$this->handle_upload_metadata( array( 'sign_request' => true ) );
		} elseif ( 'manual' === $upload_metadata ) {
			$this->sign_sso_slo_request = Utility::sanitize_post_data( 'saml_request_signed' );
		}

		parent::validate_and_save_data();
	}
}
