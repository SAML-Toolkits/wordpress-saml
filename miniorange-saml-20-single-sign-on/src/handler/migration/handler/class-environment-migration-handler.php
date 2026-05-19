<?php
/**
 * Environment Migration Handler.
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
use MOSAML\SRC\Utils\Utility;

/**
 * Environment Migration Handler.
 */
class Environment_Migration_Handler implements Migration_Handler {

	/**
	 * Migrate the environment.
	 *
	 * @param array $environments The environments to migrate.
	 * @return void
	 */
	public function migrate( $environments ) {
		foreach ( $environments as $environment ) {
			$environment_url = Utility::parse_environment_url( $environment['environment_url'] );
			DB_Utils::insert_or_update(
				Constants::DATABASE_TABLE_NAMES['environments'],
				array(
					'environment_name' => $environment['environment_name'],
					'environment_url'  => $environment_url,
					'selected'         => $environment['is_selected'],
				),
				array(
					'environment_name' => $environment['environment_name'],
					'environment_url'  => $environment_url,
				),
				'OR',
			);
		}
	}
}
