<?php
/**
 * SP Metadata Migration Handler.
 *
 * @package    MOSAML
 * @subpackage MOSAML/src/handler/migration/handler
 */

namespace MOSAML\SRC\Handler\Migration\Handler;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\SRC\Handler\Migration\Handler\Migration_Handler;
use MOSAML\SRC\Utils\DB_Utils;
use MOSAML\SRC\Constant\Constants;

/**
 * SP Metadata Migration Handler.
 */
class Sp_Metadata_Migration_Handler implements Migration_Handler {

	/**
	 * Migrate the sp metadata.
	 *
	 * @param array $sp_metadata The sp metadata to migrate.
	 * @return void
	 */
	public function migrate( $sp_metadata ) {
		foreach ( $sp_metadata as $environment_url => $sp_metadata_config ) {
			$environment = DB_Utils::get_records(
				Constants::DATABASE_TABLE_NAMES['environments'],
				array(
					'environment_url' => $environment_url,
				),
				true,
			);
			if ( empty( $environment ) ) {
				continue;
			}
			$sp_metadata_config['environment_id'] = $environment->id;
			DB_Utils::insert_or_update(
				Constants::DATABASE_TABLE_NAMES['sp_metadata'],
				$sp_metadata_config,
				array(
					'environment_id' => $environment->id,
				),
			);
		}
	}
}
