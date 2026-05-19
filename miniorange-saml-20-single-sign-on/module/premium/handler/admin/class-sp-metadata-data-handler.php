<?php
/**
 * SP Metadata Data Handler file.
 *
 * @package MOSAML\Module\Premium\Handler\Admin
 */

namespace MOSAML\Module\Premium\Handler\Admin;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\Module\Standard\Handler\Admin\SP_Metadata_Data_Handler as Standard_SP_Metadata_Data_Handler;

/**
 * Contains the download and display functionalities for SP Metadata.
 */
class SP_Metadata_Data_Handler extends Standard_SP_Metadata_Data_Handler {

	/**
	 * Function to download the SP Metadata.
	 *
	 * @param bool $is_new_certificate Whether to use the new certificate.
	 */
	public function download_sp_metadata( $is_new_certificate = false ) {
		self::set_logout_url_node();
		parent::download_sp_metadata( $is_new_certificate );
	}

	/**
	 * Function to display the SP Metadata.
	 */
	public function display_sp_metadata() {
		self::set_logout_url_node();
		parent::display_sp_metadata();
	}

	/**
	 * Function to set the logout node in the SP Metadata.
	 */
	public function set_logout_url_node() {
		$this->logout_url_node = (
			'<md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="' . esc_url( $this->sp_endpoints->sp_base_url ) . '"/>
			<md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="' . esc_url( $this->sp_endpoints->sp_base_url ) . '"/>'
		);
	}
}
