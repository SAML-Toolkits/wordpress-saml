<?php
/**
 * SSO Settings Migration Handler.
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
 * SSO Settings Migration Handler.
 */
class Sso_Settings_Migration_Handler implements Migration_Handler {

	/**
	 * Migrate the sso settings.
	 *
	 * @param array $sso_settings The sso settings to migrate.
	 * @return void
	 */
	public function migrate( $sso_settings ) {
		foreach ( $sso_settings as $site_url => $site_sso_settings ) {
			$subsite_details = DB_Utils::get_records(
				Constants::DATABASE_TABLE_NAMES['subsites'],
				array( 'site_url' => $site_url ),
				true,
				'AND',
				'',
				'ASC',
				array( '*' ),
				'LIKE'
			);
			if ( empty( $subsite_details ) ) {
				continue;
			}
			foreach ( $site_sso_settings as $idp_id => $sso_setting ) {
				if ( 'DEFAULT' === $idp_id ) {
					$where = array(
						'idp_name' => 'ALL IDPs',
					);
				} else {
					$where = array(
						'idp_id' => $idp_id,
					);
				}
				$where['environment_id'] = $subsite_details->environment_id;
				$idp_details = DB_Utils::get_records(
					Constants::DATABASE_TABLE_NAMES['idp_details'],
					$where,
					true
				);
				if ( empty( $idp_details ) ) {
					continue;
				}
				foreach ( $sso_setting as $option_name => $option_value ) {
					DB_Utils::insert_or_update(
						Constants::DATABASE_TABLE_NAMES['sso_settings'],
						array(
							'option_name'  => $option_name,
							'option_value' => $option_value,
							'idp_id'       => $idp_details->id,
							'subsite_id'   => $subsite_details->id,
						),
						array(
							'option_name' => $option_name,
							'idp_id'      => $idp_details->id,
							'subsite_id'  => $subsite_details->id,
						)
					);
				}
			}
		}
	}
}
