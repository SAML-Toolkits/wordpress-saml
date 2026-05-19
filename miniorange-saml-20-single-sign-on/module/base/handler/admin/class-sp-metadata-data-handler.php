<?php
/**
 * SP Metadata Data Handler file.
 *
 * @package MOSAML\Module\Base\Handler\Admin
 */

namespace MOSAML\Module\Base\Handler\Admin;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\SRC\Constant\Plugin_Files_Constants;
use MOSAML\SRC\Utils\DB_Utils;
use MOSAML\SRC\Utils\Utility;

/**
 * SP Metadata Data Handler class.
 *
 * This class handles the data for the SP metadata.
 *
 * @package MOSAML\Module\Base\Handler\Admin
 */
class SP_Metadata_Data_Handler {

	/**
	 * SP Endpoints.
	 *
	 * @var SP_Endpoints_Data_Handler
	 */
	public $sp_endpoints;

	/**
	 * SP Certificate.
	 *
	 * @var object
	 */
	public $sp_certificate;

	/**
	 * SP Organization Details.
	 *
	 * @var SP_Organization_Data_Handler
	 */
	public $sp_organization_details;


	/**
	 * Certificate Node.
	 *
	 * @var string
	 */
	public $certificate_node;

	/**
	 * Logout URL Node.
	 *
	 * @var string
	 */
	public $logout_url_node;

	/**
	 * Extension Node.
	 *
	 * @var string
	 */
	public $extension_node;

	/**
	 * Name ID Format Node.
	 *
	 * @var string
	 */
	public $name_id_format_node;

	/**
	 * Certificate Expiry Date.
	 *
	 * @var int
	 */
	public $certificate_expiry_date;

	/**
	 * Constructor.
	 */
	public function __construct() {
		$selected_environment_id         = DB_Utils::get_environment_details( 'id', false );
		$this->sp_endpoints              = ( new SP_Endpoints_Data_Handler() )->get_data( array( 'environment_id' => $selected_environment_id ) );
		$this->sp_endpoints->sp_base_url = $this->sp_endpoints->sp_base_url . '/';
		$this->sp_organization_details   = Utility::get_handler_object( 'sp_organization_data', true, 'Admin' )->get_data( array( 'environment_id' => $selected_environment_id ) );
		$this->sp_certificate            = ( new Certificate_Data_Handler() )->get_data( array( 'environment_id' => $selected_environment_id ) );
	}

	/**
	 * Function to download the SP Metadata.
	 *
	 * @param bool $is_new_certificate Whether to use the new certificate.
	 */
	public function download_sp_metadata( $is_new_certificate = false ) {
		if ( ob_get_contents() ) {
			// TODO: Check if this is required.
			ob_clean();
		}
		if ( $is_new_certificate ) {
			$filename = 'NewMetadata.xml';
		} else {
			$filename = 'Metadata.xml';
		}
		header( 'Content-Disposition: attachment; filename="' . $filename . '"' );
		require_once Plugin_Files_Constants::TEMPLATE_SP_METADATA;
	}

	/**
	 * Function to download the SP Certificate.
	 *
	 * @param bool $is_new_certificate Whether to use the new certificate.
	 */
	public function download_certificate( $is_new_certificate = false ) {}

	/**
	 * Function to display the SP Metadata.
	 */
	public function display_sp_metadata() {
		if ( ob_get_contents() ) {
			// TODO: Check if this is required.
			ob_clean();
		}
		header( 'Content-Type: text/xml' );
		require_once Plugin_Files_Constants::TEMPLATE_SP_METADATA;
	}
}
