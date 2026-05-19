<?php
/**
 * Normalized Migration Model.
 *
 * @package    MOSAML
 * @subpackage MOSAML/src/handler/migration/model
 */

namespace MOSAML\SRC\Handler\Migration\Model;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Normalized Migration Model.
 */
class Normalized_Migration_Model {

	/**
	 * Environments.
	 *
	 * @var array
	 */
	public $environments = array();

	/**
	 * Subsites.
	 *
	 * @var array
	 */
	public $subsites = array();

	/**
	 * IDP Details.
	 *
	 * @var array
	 */
	public $idp_details = array();

	/**
	 * SP Metadata.
	 *
	 * @var array
	 */
	public $sp_metadata = array();

	/**
	 * Attribute Mapping.
	 *
	 * @var array
	 */
	public $attribute_mapping = array();

	/**
	 * Role Mapping.
	 *
	 * @var array
	 */
	public $role_mapping = array();

	/**
	 * SSO Settings.
	 *
	 * @var array
	 */
	public $sso_settings = array();

	/**
	 * Global Options.
	 *
	 * @var array
	 */
	public $global_options = array();
}
