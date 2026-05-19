<?php
/**
 * Migration Initializer.
 *
 * @package    MOSAML
 * @subpackage MOSAML/src/handler/migration
 */

namespace MOSAML\SRC\Handler\Migration;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\SRC\Handler\Migration\Helper\Migration_Helper;
use MOSAML\SRC\Handler\Migration\Handler\Environment_Migration_Handler;
use MOSAML\SRC\Handler\Migration\Handler\Idp_Details_Migration_Handler;
use MOSAML\SRC\Handler\Migration\Handler\Attribute_Migration_Handler;
use MOSAML\SRC\Handler\Migration\Handler\Role_Migration_Handler;
use MOSAML\SRC\Handler\Migration\Handler\Sso_Settings_Migration_Handler;
use MOSAML\SRC\Handler\Migration\Handler\Sp_Metadata_Migration_Handler;
use MOSAML\SRC\Handler\Migration\Handler\Subsite_Migration_Handler;
use MOSAML\SRC\Handler\Migration\Handler\Global_Option_Migration_Handler;
use MOSAML\SRC\Constant\Constants;

/**
 * Migration Initializer.
 */
class Migration_Initializer {

	/**
	 * Initialize the migration.
	 *
	 * @return void
	 */
	public static function initialize() {

		if ( ! Migration_Helper::is_migration_needed() ) {
			return;
		}

		update_option( Constants::MIGRATION_STATUS, 'in_progress' );

		$mapper           = Migration_Helper::get_mapper();
		$normalized_model = $mapper->map();

		self::migrate_data( $normalized_model );
	}

	/**
	 * Migrate the data.
	 *
	 * @param Normalized_Migration_Model $normalized_model The normalized model.
	 * @return void
	 */
	private static function migrate_data( $normalized_model ) {
		$env_handler = new Environment_Migration_Handler();
		$env_handler->migrate( $normalized_model->environments );

		$global_option_handler = new Global_Option_Migration_Handler();
		$global_option_handler->migrate( $normalized_model->global_options );

		$idp_handler = new Idp_Details_Migration_Handler();
		$idp_handler->migrate( $normalized_model->idp_details );

		$sp_handler = new Sp_Metadata_Migration_Handler();
		$sp_handler->migrate( $normalized_model->sp_metadata );

		$subsite_handler = new Subsite_Migration_Handler();
		$subsite_handler->migrate( $normalized_model->subsites );

		$attr_handler = new Attribute_Migration_Handler();
		$attr_handler->migrate( $normalized_model->attribute_mapping );

		$role_handler = new Role_Migration_Handler();
		$role_handler->migrate( $normalized_model->role_mapping );

		$sso_handler = new Sso_Settings_Migration_Handler();
		$sso_handler->migrate( $normalized_model->sso_settings );

		update_option( Constants::MIGRATION_STATUS, 'completed' );
	}
}
