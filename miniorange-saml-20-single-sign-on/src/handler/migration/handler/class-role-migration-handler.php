<?php
/**
 * Role Migration Handler.
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
 * Role Migration Handler.
 */
class Role_Migration_Handler implements Migration_Handler {

	/**
	 * Migrate the role.
	 *
	 * @param array $roles The roles to migrate.
	 * @return void
	 */
	public function migrate( $roles ) {
		foreach ( $roles as $wp_site_url => $role_mappings ) {
			$subsite_details = DB_Utils::get_records(
				Constants::DATABASE_TABLE_NAMES['subsites'],
				array(
					'site_url' => $wp_site_url,
				),
				true,
				'AND',
				'',
				'ASC',
				array( '*' ),
				'LIKE'
			);

			$environment = DB_Utils::get_records(
				Constants::DATABASE_TABLE_NAMES['environments'],
				array(
					'environment_url' => Utility::parse_environment_url( $wp_site_url ),
				),
				true,
			);
			if ( empty( $subsite_details ) || ! is_array( $role_mappings ) ) {
				continue;
			}
			foreach ( $role_mappings as $idp_id => $role_mapping ) {
				$where = array( 'idp_id' => $idp_id, 'environment_id' => $environment->id );
				if ( 'DEFAULT' === $idp_id ) {
					$where = array( 'idp_name' => 'ALL IDPs', 'environment_id' => $environment->id );
				}
				$idp_details = DB_Utils::get_records(
					Constants::DATABASE_TABLE_NAMES['idp_details'],
					$where,
					true
				);
				if ( empty( $idp_details ) ) {
					continue;
				}
				foreach ( $role_mapping as $role_key => $configured_group_values ) {
					$configured_group_values = explode( ';', rtrim($configured_group_values, ';') );
					foreach ( $configured_group_values as $configured_group_value ) {
						DB_Utils::insert_or_update(
							Constants::DATABASE_TABLE_NAMES['role_mapping'],
							array(
								'role_name'      => $role_key,
								'idp_group_name' => $configured_group_value,
								'idp_id'         => $idp_details->id,
								'subsite_id'     => $subsite_details->id,
							),
							array(
								'role_name'      => $role_key,
								'idp_group_name' => $configured_group_value,
								'idp_id'         => $idp_details->id,
								'subsite_id'     => $subsite_details->id,
							),
						);
					}
				}
			}
		}
	}
}
