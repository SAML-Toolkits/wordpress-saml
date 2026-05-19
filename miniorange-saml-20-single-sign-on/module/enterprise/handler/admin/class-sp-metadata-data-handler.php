<?php
/**
 * SP Metadata Data Handler file.
 *
 * @package MOSAML\Module\Enterprise\Handler\Admin
 */

namespace MOSAML\Module\Enterprise\Handler\Admin;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\Module\Premium\Handler\Admin\SP_Metadata_Data_Handler as Premium_SP_Metadata_Data_Handler;

/**
 * Contains the download and display functionalities for SP Metadata.
 */
class SP_Metadata_Data_Handler extends Premium_SP_Metadata_Data_Handler {

	/**
	 * Function to download the SP Metadata.
	 *
	 * @param bool $is_new_certificate Whether to use the new certificate.
	 */
	public function download_sp_metadata( $is_new_certificate = false ) {
		self::set_extension_node();
		parent::download_sp_metadata( $is_new_certificate );
	}

	/**
	 * Function to display the SP Metadata.
	 */
	public function display_sp_metadata() {
		self::set_extension_node();
		parent::display_sp_metadata();
	}

	/**
	 * Function to set the extension node in the SP Metadata.
	 */
	public function set_extension_node() {
		$this->extension_node = (
			'<md:Extensions>
        <idpdisc:DiscoveryResponse xmlns:idpdisc="urn:oasis:names:tc:SAML:profiles:SSO:idp-discovery-protocol" index="1"
        Binding="urn:oasis:names:tc:SAML:profiles:SSO:idp-discovery-protocol"
        Location="' . esc_url( $this->sp_endpoints->sp_base_url ) . '"/>
        </md:Extensions>'
		);
	}
}
