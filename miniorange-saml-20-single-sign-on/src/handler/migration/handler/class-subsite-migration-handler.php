<?php
/**
 * Subsite Migration Handler.
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
 * Subsite Migration Handler.
 */
class Subsite_Migration_Handler implements Migration_Handler {

	/**
	 * Migrate the subsite.
	 *
	 * @param array $subsites The subsites to migrate.
	 * @return void
	 */
	public function migrate( $subsites ) {
		foreach ( $subsites as $environment_url => $subsite ) {
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
			$subsite['environment_id'] = $environment->id;
			DB_Utils::insert_or_update(
				Constants::DATABASE_TABLE_NAMES['subsites'],
				$subsite,
				array(
					'environment_id' => $environment->id,
					'site_url'       => $subsite['site_url'],
				),
			);
		}
	}
}
