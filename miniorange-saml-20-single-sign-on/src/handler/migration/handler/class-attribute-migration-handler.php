<?php
/**
 * Attribute Migration Handler.
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
 * Attribute Migration Handler.
 */
class Attribute_Migration_Handler implements Migration_Handler {

	/**
	 * Migrate the attributes.
	 *
	 * @param array $attributes The attributes to migrate.
	 * @return void
	 */
	public function migrate( $attributes ) {
		foreach ( $attributes as $environment_url => $environment_attribute_mappings ) {
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
			foreach ( $environment_attribute_mappings as $idp_id => $attribute_mappings ) {
				$where = array( 'idp_id' => $idp_id, 'environment_id' => $environment->id );
				if ( 'DEFAULT' === $idp_id ) {
					$where = array( 'idp_name' => 'All IDPs', 'environment_id' => $environment->id );
				}
				$idp_details = DB_Utils::get_records(
					Constants::DATABASE_TABLE_NAMES['idp_details'],
					$where,
					true
				);
				if ( empty( $idp_details ) ) {
					continue;
				}
				foreach ( $attribute_mappings as $attribute_mapping_key => $attribute_mapping ) {
					if ( 'custom_attributes_to_display' === $attribute_mapping_key ) {
						continue;
					}
					if ( 'custom_attributes' === $attribute_mapping_key ) {
						$custom_attributes_to_display = $attribute_mappings['custom_attributes_to_display'] ?? null;

						$index = 0;
						foreach ( $attribute_mapping as $custom_attribute_key => $custom_attribute_value ) {
							$display = in_array( $index, (array) $custom_attributes_to_display, true );
							DB_Utils::insert_or_update(
								Constants::DATABASE_TABLE_NAMES['attribute_mapping'],
								array(
									'option_name'  => $custom_attribute_key,
									'option_value' => $custom_attribute_value,
									'idp_id'       => $idp_details->id,
									'display'      => $display,
									'custom'       => true,
								),
								array(
									'idp_id'      => $idp_details->id,
									'option_name' => $custom_attribute_key,
									'custom'      => true,
								),
							);
							++$index;
						}
						continue;
					}
					if ( 'do_not_update_display_name' === $attribute_mapping_key ) {
						DB_Utils::insert_or_update(
							Constants::DATABASE_TABLE_NAMES['attribute_mapping'],
							array(
								'option_name'  => 'do_not_update_display_name',
								'option_value' => $attribute_mapping,
								'idp_id'       => $idp_details->id,
								'custom'       => false,
								'display'      => false,
							),
							array(
								'idp_id'      => $idp_details->id,
								'option_name' => 'do_not_update_display_name',
							),
						);
						continue;
					}
					DB_Utils::insert_or_update(
						Constants::DATABASE_TABLE_NAMES['attribute_mapping'],
						array(
							'option_name'  => $attribute_mapping_key,
							'option_value' => $attribute_mapping,
							'idp_id'       => $idp_details->id,
							'custom'       => false,
							'display'      => false,
						),
						array(
							'idp_id'      => $idp_details->id,
							'option_name' => $attribute_mapping_key,
							'custom'      => false,
						),
					);
				}
			}
		}
	}
}
