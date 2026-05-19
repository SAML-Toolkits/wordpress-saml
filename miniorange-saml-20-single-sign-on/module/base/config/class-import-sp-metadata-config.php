<?php
/**
 * Base Module - Import SP Metadata Configuration Class
 *
 * Handles SP metadata configuration data import for the base module.
 *
 * @package MOSAML\Module\Base\Config
 * @since 1.0.0
 */

namespace MOSAML\Module\Base\Config;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\SRC\Constant\Constants;

/**
 * Base Import SP Metadata Configuration Class
 */
class Import_SP_Metadata_Config {

	/**
	 * Get the database table name
	 *
	 * @return string The table name
	 */
	protected function get_table_name() {
		return Constants::DATABASE_TABLE_NAMES['sp_metadata'];
	}

	/**
	 * SP Base URL
	 *
	 * @var string
	 */
	public $sp_base_url = '';

	/**
	 * SP Entity ID
	 *
	 * @var string
	 */
	public $sp_entity_id = '';

	/**
	 * Public Key
	 *
	 * @var string
	 */
	public $public_key = '';

	/**
	 * Private Key
	 *
	 * @var string
	 */
	public $private_key = '';

	/**
	 * Is Custom Certificate
	 *
	 * @var string
	 */
	public $is_custom_certificate = '';

	/**
	 * Organization Name
	 *
	 * @var string
	 */
	public $organization_name = '';

	/**
	 * Organization Display Name
	 *
	 * @var string
	 */
	public $organization_display_name = '';

	/**
	 * Organization URL
	 *
	 * @var string
	 */
	public $organization_url = '';

	/**
	 * Technical Person Name
	 *
	 * @var string
	 */
	public $technical_person_name = '';

	/**
	 * Technical Person Email
	 *
	 * @var string
	 */
	public $technical_person_email = '';

	/**
	 * Support Person Name
	 *
	 * @var string
	 */
	public $support_person_name = '';

	/**
	 * Support Person Email
	 *
	 * @var string
	 */
	public $support_person_email = '';

	/**
	 * Environment ID
	 *
	 * @var int
	 */
	public $environment_id;
}
