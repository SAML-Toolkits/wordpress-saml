<?php
/**
 * Idp Details Migration Handler.
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
 * Idp Details Migration Handler.
 */
class Idp_Details_Migration_Handler implements Migration_Handler {

	/**
	 * Migrate the idp details.
	 *
	 * @param array $idp_details The idp details to migrate.
	 * @return void
	 */
	public function migrate( $idp_details ) {
		foreach ( $idp_details as $environment_url => $idps_detail ) {
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
			foreach ( $idps_detail as $idp_id => $idp_detail ) {
				$idp_detail['environment_id'] = $environment->id;
				$where = array(
					'environment_id' => $environment->id,
				);
				if( $idp_detail['idp_name'] !== 'All IDPs' ) {
					$where['idp_id'] = $idp_id;
				} else {
					$where['idp_name'] = 'All IDPs';
				}
				DB_Utils::insert_or_update(
					Constants::DATABASE_TABLE_NAMES['idp_details'],
					$idp_detail,
					$where,
				);
			}
		}
	}
}
