<?php
/**
 * Premium Auto Redirection Data Handler.
 *
 * @package miniorange-saml-20-single-sign-on/module/premium/handler/admin
 */

namespace MOSAML\Module\Premium\Handler\Admin;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\Module\Standard\Handler\Admin\Site_Auto_Redirection_Data_Handler as Standard_Site_Auto_Redirection_Data_Handler;
use MOSAML\SRC\Interfaces\Form_Data_Handler_Interface;
use MOSAML\SRC\Utils\Utility;

/**
 * Premium Auto Redirection Data Handler.
 */
class Site_Auto_Redirection_Data_Handler extends Standard_Site_Auto_Redirection_Data_Handler implements Form_Data_Handler_Interface {

	/**
	 * Validate and save data.
	 *
	 * @return void
	 */
	public function validate_and_save_data() {
		$site_auto_redirection_option       = 'public_page' !== Utility::sanitize_post_data( 'mo_saml_auto_redirection_options' ) ? Utility::sanitize_post_data( 'mo_saml_auto_redirection_options' ) : $this->site_auto_redirection_option;
		$this->site_auto_redirection_option = ! $this->is_site_auto_redirection_option_default ? $this->site_auto_redirection_option : $site_auto_redirection_option;

		$this->is_site_auto_redirection_option_default = false;
		parent::validate_and_save_data();
	}
}
