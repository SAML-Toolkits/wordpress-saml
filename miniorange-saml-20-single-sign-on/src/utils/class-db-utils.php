<?php
/**
 * Database Utilities Class.
 *
 * @package    MOSAML
 * @subpackage MOSAML/src/utils
 */

namespace MOSAML\SRC\Utils;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\SRC\Database\Database_Migrator;
use MOSAML\SRC\Database\DB_Queries;
use MOSAML\SRC\Exception\Database_Exception;
use MOSAML\SRC\Utils\Utility;
use MOSAML\SRC\Constant\Constants;
use MOSAML\SRC\Utils\Certificate_Utility;

/**
 * Database Utilities Class.
 */
class DB_Utils {

	/**
	 * Create all required database tables and initialize the database.
	 *
	 * @return bool|null True if the tables were created, false otherwise, null if the database version is the same as the current database version.
	 */
	public static function create_tables_and_initialize() {
		$latest = Database_Migrator::get_latest_migration_version();
		if ( null === $latest ) {
			return false;
		}

		if ( ! self::all_tables_exist() || version_compare( self::get_current_db_version(), $latest, '<' ) ) {
			return self::initialize_database();
		}

		return true;
	}

	/**
	 * Initialize the database.
	 *
	 * @return bool True if the database was initialized, false otherwise.
	 */
	public static function initialize_database() {
		if ( ! self::create_tables_in_database() ) {
			return false;
		}

		if ( ! self::initialize_tables_data() ) {
			return false;
		}

		self::initialize_default_plugin_options();

		return true;
	}

	/**
	 * Create the tables in the database.
	 *
	 * @return bool True if the tables were created, false otherwise.
	 */
	public static function create_tables_in_database() {
		if ( ! Database_Migrator::instance()->run_migrations() ) {
			return false;
		}

		return self::all_tables_exist();
	}

	/**
	 * Initialize the tables data.
	 *
	 * @return bool True if the tables data was initialized, false otherwise.
	 */
	public static function initialize_tables_data() {
		$environment_id = self::initialize_environment_table( str_replace( ' ', '_', get_bloginfo( 'name' ) ), Utility::parse_environment_url( site_url() ) );

		if ( ! $environment_id ) {
			return false;
		}

		if ( ! self::initialize_idp_details_table( $environment_id ) ) {
			return false;
		}

		if ( ! self::initialize_subsites_table( $environment_id ) ) {
			return false;
		}

		if ( ! self::initialize_sp_metadata_table( $environment_id ) ) {
			return false;
		}

		if ( ! self::initialize_attribute_mapping_table( $environment_id ) ) {
			return false;
		}

		return true;
	}

	/**
	 * Initialize default plugin options.
	 *
	 * Sets default values for WordPress options that control plugin behavior.
	 * This method should be called on plugin activation to ensure consistent state.
	 *
	 * @return void
	 */
	public static function initialize_default_plugin_options() {
		update_option( Constants::KEEP_SETTINGS_OPTION_NAME, 'checked' );
		update_option( Constants::ENABLE_BACKUP_SETTINGS, 'checked' );
		update_option( Constants::SEND_PLUGIN_CONFIG_OPTION_NAME, 'checked' );
		$latest = Database_Migrator::get_latest_migration_version();
		update_option( Constants::DB_VERSION_OPTION_NAME, $latest ? $latest : Constants::DB_VERSION );
		update_option( Constants::DATABASE_UPDATE_STATUS, 'completed' );
	}

	/**
	 * Get the current applied schema version (semver from SQL migrations).
	 *
	 * @return string
	 */
	public static function get_current_db_version() {
		$stored = get_option( Constants::DB_VERSION_OPTION_NAME, false );
		if ( false === $stored || '' === $stored ) {
			return '0.0.0';
		}

		$str = is_scalar( $stored ) ? (string) $stored : '';
		if ( preg_match( '/^\d+\.\d+\.\d+$/', $str ) ) {
			return $str;
		}

		// Legacy: option held a numeric marker (e.g. 1.0) before semver migrations.
		return '1.0.0';
	}

	/**
	 * Check if a table exists in the database.
	 *
	 * @param string|array $table_names The table names.
	 * @return string|array The table name if it exists, array of table names if they exist, empty array if none exist.
	 */
	public static function existing_tables( $table_names ) {
		$db_queries = DB_Queries::instance();

		if ( ! is_array( $table_names ) ) {
			$table_name = $db_queries->table_exists_query( $table_names );
			return ! empty( $table_name ) ? $table_name : '';
		}

		$existing_tables = array_filter(
			$table_names,
			function ( $table ) use ( $db_queries ) {
				return $db_queries->table_exists_query( $table );
			}
		);

		return ! empty( $existing_tables ) ? $existing_tables : array();
	}

	/**
	 * Check if all tables exist in the database.
	 *
	 * @return bool True if all tables exist, false otherwise.
	 */
	public static function all_tables_exist() {
		$existing_tables = self::existing_tables( Constants::DATABASE_TABLE_NAMES );
		return is_countable( $existing_tables ) && count( $existing_tables ) === count( Constants::DATABASE_TABLE_NAMES );
	}

	/**
	 * Get multiple records from the database.
	 *
	 * @param string $table_name Table name without prefix.
	 * @param array  $where      Where clause.
	 * @param bool   $single_record Whether to return a single record or multiple records.
	 * @param string $operator   Operator to use for the where clause.
	 * @param string $order_by   Order by clause.
	 * @param string $order      Order direction (ASC or DESC).
	 * @param array  $columns    Columns to fetch.
	 * @param string $predicate The predicate to use for the where clause.
	 * @return object|array|null|void The record object or array of record objects or null or void if no records are found.
	 */
	public static function get_records( $table_name, $where = array(), $single_record = false, $operator = 'AND', $order_by = '', $order = 'ASC', $columns = array( '*' ), $predicate = '=' ) {
		return DB_Queries::instance()->get_query( $table_name, $where, $operator, $single_record, $order_by, $order, $columns, $predicate );
	}

	/**
	 * Check if a record exists in the database.
	 *
	 * @param string $table_name Table name without prefix.
	 * @param array  $where      Where clause.
	 * @return bool True if the record exists, false otherwise.
	 */
	public static function is_record_exists( $table_name, $where = array() ) {
		return ! empty( self::get_records( $table_name, $where, true, 'AND', '', '', array( 'id' ) ) );
	}

	/**
	 * Insert or update a record in the database.
	 *
	 * @param string $table_name Table name without prefix.
	 * @param array  $data       Data to save.
	 * @param array  $where      Where clause for update.
	 * @param string $operator   Operator to use for the where clause.
	 * @param bool   $return_id  Whether to return the id of the inserted row.
	 * @return int|false The id of the inserted row or false on failure.
	 */
	public static function insert_or_update( $table_name, $data, $where = array(), $operator = 'AND', $return_id = false ) {
		// Fire hook for settings updates in sso_settings table.
		if ( Constants::DATABASE_TABLE_NAMES['sso_settings'] === $table_name && isset( $data['option_name'] ) && isset( $data['option_value'] ) ) {
			/**
			 * Action hook fired when a SAML setting is updated.
			 *
			 * @param string $key   The option name (setting key).
			 * @param mixed  $value The option value (setting value).
			 */
			do_action( 'mosaml_settings_updated_internal', $data['option_name'], $data['option_value'] );
		}

		return DB_Queries::instance()->insert_or_update_query( $table_name, $data, $where, $operator, $return_id );
	}

	/**
	 * Initialize the environment table.
	 *
	 * @param string $environment_name The name of the environment.
	 * @param string $environment_url The URL of the environment.
	 *
	 * @return bool|int The id of the inserted row or true if the record exists, false on failure.
	 */
	public static function initialize_environment_table( $environment_name, $environment_url ) {
		$environment = self::get_records(
			Constants::DATABASE_TABLE_NAMES['environments'],
			array(
				'environment_name' => $environment_name,
				'environment_url'  => $environment_url,
				'selected'         => true,
			),
			true,
			'OR'
		);
		if ( ! $environment ) {
			return self::insert_or_update(
				Constants::DATABASE_TABLE_NAMES['environments'],
				array(
					'environment_name' => $environment_name,
					'environment_url'  => $environment_url,
					'selected'         => true,
				),
				array(
					'environment_name' => $environment_name,
					'environment_url'  => $environment_url,
				),
				'OR',
				true
			);
		}
		return ! empty( $environment->id ) ? (int) $environment->id : false;
	}

	/**
	 * Delete a record from the database.
	 *
	 * @param string $table_name Table name without prefix.
	 * @param array  $where      Where clause.
	 * @param string $where_operator Where operator.
	 * @param string $in_clause_key In clause key.
	 * @param array  $in_clause_value In clause value.
	 * @param string $in_clause_type In clause type.
	 * @param string $in_clause_operator In clause operator.
	 * @return int|false The number of rows affected, or false on error.
	 * @throws Database_Exception If database operation fails.
	 */
	public static function delete_records( $table_name, $where, $where_operator = 'AND', $in_clause_key = '', $in_clause_value = array(), $in_clause_type = 'IN', $in_clause_operator = 'AND' ) {
		// Fire hook for settings deletions in sso_settings table.
		if ( Constants::DATABASE_TABLE_NAMES['sso_settings'] === $table_name && isset( $where['option_name'] ) ) {
			/**
			 * Action hook fired when a SAML setting is deleted.
			 *
			 * @param string $key The option name (setting key) that was deleted.
			 */
			do_action( 'mosaml_settings_deleted_internal', $where['option_name'] );
		}

		try {
			if ( $in_clause_key && $in_clause_value ) {
				return DB_Queries::instance()->prepare_and_run_query( 'DELETE', $table_name, array(), $where, $where_operator, $in_clause_key, $in_clause_value, $in_clause_type, $in_clause_operator );
			}
			return DB_Queries::instance()->delete_query( $table_name, $where );
		} catch ( \Exception $e ) {
			// phpcs:ignore WordPress.Security.EscapeOutput.ExceptionNotEscaped -- Exception message is not output to user; safe to skip escaping here.
			throw new Database_Exception( 'Failed to delete record from the table: ' . $e->getMessage() );
		}
	}

	/**
	 * Get the current environment details.
	 *
	 * @param string $column The column to return.
	 * @param bool   $current_env Whether to return the current environment details. Default is true.
	 * @return object|null|string The current environment details.
	 */
	public static function get_environment_details( $column = 'id', $current_env = true ) {
		$environment_details  = array();
		$multiple_env_enabled = get_option( Constants::ENABLE_MULTIPLE_ENVIRONMENTS_OPTION_NAME );
		$site_env_url         = Utility::parse_environment_url( site_url() );

		if ( $current_env || Feature_Control::is_feature_locked( 4, false ) || 'checked' !== $multiple_env_enabled ) {
			$environment_details = self::get_records( Constants::DATABASE_TABLE_NAMES['environments'], array( 'environment_url' => $site_env_url ), true );
		} else {
			$environment_details = self::get_records( Constants::DATABASE_TABLE_NAMES['environments'], array( 'selected' => true ), true );
		}

		if ( ! $environment_details ) {
			$environment_details = self::get_records( Constants::DATABASE_TABLE_NAMES['environments'], array( 'environment_url' => $site_env_url ), true );
		}

		if ( ! $environment_details ) {
			$environment_details = self::get_records( Constants::DATABASE_TABLE_NAMES['environments'], array(), true, 'AND', 'id', 'ASC' );
		}

		if ( ! empty( $column ) ) {
			if ( is_object( $environment_details ) && isset( $environment_details->$column ) ) {
				return $environment_details->$column;
			} else {
				return '';
			}
		}

		return is_object( $environment_details ) ? $environment_details : (object) array();
	}

	/**
	 * Drop tables from the database.
	 *
	 * @param array $table_names Table names without prefix.
	 * @return void
	 * @throws Database_Exception If database operation fails.
	 */
	public static function drop_tables( $table_names = array() ) {
		if ( empty( $table_names ) ) {
			return;
		}

		global $wpdb;
		try {
			// Temporarily disable foreign key checks to avoid constraint errors.
			// phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
			$wpdb->query( 'SET FOREIGN_KEY_CHECKS = 0' );

			foreach ( $table_names as $table_name ) {
				DB_Queries::instance()->drop_query( $table_name );
			}

			// Re-enable foreign key checks.
			// phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
			$wpdb->query( 'SET FOREIGN_KEY_CHECKS = 1' );
		} catch ( \Exception $e ) {
			// Re-enable foreign key checks even if an error occurred.
			// phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
			$wpdb->query( 'SET FOREIGN_KEY_CHECKS = 1' );
			// phpcs:ignore WordPress.Security.EscapeOutput.ExceptionNotEscaped -- Exception message is not output to user; safe to skip escaping here.
			throw new Database_Exception( 'Failed to drop table: ' . $e->getMessage() );
		}
	}

	/**
	 * Initialize the SP metadata table.
	 *
	 * @param string $environment_id The environment ID.
	 * @param string $environment_url The environment URL.
	 * @return bool True if the table was initialized, false otherwise.
	 */
	public static function initialize_sp_metadata_table( $environment_id = '', $environment_url = '' ) {
		$environment_id = $environment_id ? $environment_id : self::get_environment_details( 'id' );

		// Validate environment_id is not empty.
		if ( empty( $environment_id ) ) {
			return false;
		}

		$existing_record = self::get_records(
			Constants::DATABASE_TABLE_NAMES['sp_metadata'],
			array( 'environment_id' => $environment_id ),
			true
		);

		if ( $existing_record ) {
			if ( empty( $existing_record->public_key ) || empty( $existing_record->private_key ) ) {
				Certificate_Utility::save_sp_certificate( $environment_id );
			}
			return true;
		}

		$sp_base_url = ! empty( $environment_url ) ? $environment_url : home_url();
		if ( ! preg_match( '/^https?:\/\//i', $sp_base_url ) ) {
			$scheme      = Utility::mo_saml_is_ssl() ? 'https://' : 'http://';
			$sp_base_url = $scheme . ltrim( $sp_base_url, '/' );
		}

		$sp_entity_id = $sp_base_url . Constants::SP_ENTITY_ID;

		$result = self::insert_or_update(
			Constants::DATABASE_TABLE_NAMES['sp_metadata'],
			array(
				'sp_base_url'    => $sp_base_url,
				'sp_entity_id'   => $sp_entity_id,
				'environment_id' => $environment_id,
			),
			array( 'environment_id' => $environment_id )
		);

		if ( ! $result ) {
			return false;
		}

		$record = self::get_records( Constants::DATABASE_TABLE_NAMES['sp_metadata'], array( 'environment_id' => $environment_id ), true );
		if ( ! $record || empty( $record->public_key ) || empty( $record->private_key ) ) {
			Certificate_Utility::save_sp_certificate( $environment_id );
		}

		return true;
	}

	/**
	 * Initialize the attribute mapping table.
	 *
	 * @param string $environment_id The environment ID.
	 * @return bool True if the table was initialized, false otherwise.
	 */
	public static function initialize_attribute_mapping_table( $environment_id = '' ) {
		if ( empty( $environment_id ) ) {
			return false;
		}

		$all_idp_details = self::get_records(
			Constants::DATABASE_TABLE_NAMES['idp_details'],
			array(
				'environment_id' => $environment_id,
				'idp_name'       => 'ALL IDPs',
			),
			true
		);
		if ( ! $all_idp_details ) {
			return false;
		}
		$all_idp_id = $all_idp_details->id;

		$record = self::is_record_exists(
			Constants::DATABASE_TABLE_NAMES['attribute_mapping'],
			array(
				'idp_id' => $all_idp_id,
			)
		);
		if ( ! $record ) {
			self::insert_or_update(
				Constants::DATABASE_TABLE_NAMES['attribute_mapping'],
				array(
					'idp_id'       => $all_idp_id,
					'option_name'  => 'user_name',
					'option_value' => 'NameID',
					'custom'       => 0,
					'display'      => 0,
				),
				array(
					'idp_id'      => $all_idp_id,
					'option_name' => 'user_name',
				),
			);

			self::insert_or_update(
				Constants::DATABASE_TABLE_NAMES['attribute_mapping'],
				array(
					'idp_id'       => $all_idp_id,
					'option_name'  => 'email',
					'option_value' => 'NameID',
					'custom'       => 0,
					'display'      => 0,
				),
				array(
					'idp_id'      => $all_idp_id,
					'option_name' => 'email',
				),
			);
		}
		return true;
	}

	/**
	 * Initialize the IDP details table.
	 *
	 * @param string $environment_id The environment ID.
	 * @return bool|int The id of the inserted row or true if the record exists, false on failure.
	 */
	public static function initialize_idp_details_table( $environment_id = '' ) {
		$environment_id = $environment_id ? $environment_id : self::get_environment_details( 'id' );
		$record         = self::get_records( Constants::DATABASE_TABLE_NAMES['idp_details'], array( 'environment_id' => $environment_id ), true );
		if ( ! $record ) {
			$idp_id = Utility::generate_idp_id();
			return self::insert_or_update(
				Constants::DATABASE_TABLE_NAMES['idp_details'],
				array(
					'environment_id'  => $environment_id,
					'idp_name'        => Constants::DEFAULT_IDP_NAME,
					'entity_id'       => Constants::DEFAULT_IDP_NAME,
					'sso_url'         => Constants::DEFAULT_IDP_NAME,
					'slo_url'         => Constants::DEFAULT_IDP_NAME,
					'idp_certificate' => Constants::DEFAULT_IDP_NAME,
					'idp_id'          => $idp_id,
					'status'          => 'inactive',
					'name_id_format'  => Constants::NAMEID_FORMATS['unspecified'],
				),
				array(
					'environment_id' => $environment_id,
					'idp_id'         => $idp_id,
				),
			);
		}
		return true;
	}

	/**
	 * Initialize the subsites table.
	 *
	 * @param string $environment_id The environment ID.
	 * @param string $blog_id The blog ID.
	 * @param string $site_url The site URL.
	 * @return bool|int The id of the inserted row or true if the record exists, false on failure.
	 */
	public static function initialize_subsites_table( $environment_id = '', $blog_id = '', $site_url = '' ) {
		$environment_id = $environment_id ? $environment_id : self::get_environment_details( 'id' );
		$blog_id        = $blog_id ? $blog_id : Constants::DEFAULT_BLOG_ID;
		$site_url       = $site_url ? $site_url : site_url();
		$record         = self::get_records(
			Constants::DATABASE_TABLE_NAMES['subsites'],
			array(
				'environment_id' => $environment_id,
				'blog_id'        => $blog_id,
				'site_url'       => $site_url,
			),
			true
		);
		if ( ! $record ) {
			return self::insert_or_update(
				Constants::DATABASE_TABLE_NAMES['subsites'],
				array(
					'environment_id' => $environment_id,
					'blog_id'        => $blog_id,
					'site_url'       => $site_url,
				),
				array( 'environment_id' => $environment_id ),
			);
		}
		return true;
	}

	/**
	 * Get the default inserted IDP details.
	 *
	 * @param string $column The column to return.
	 * @param string $environment_id The environment ID.
	 * @return object|null|string The default inserted IDP details.
	 */
	public static function get_default_inserted_idp_details( $column = '', $environment_id = '' ) {
		$environment_id = $environment_id ? $environment_id : self::get_environment_details( 'id' );
		$idp_details    = self::get_records(
			Constants::DATABASE_TABLE_NAMES['idp_details'],
			array(
				'environment_id' => $environment_id,
				'idp_name'       => Constants::DEFAULT_IDP_NAME,
			),
			true
		);
		if ( ! empty( $idp_details ) ) {
			return ! empty( $column ) ? $idp_details->$column : $idp_details;
		}
		return ! empty( $column ) ? '' : null;
	}

	/**
	 * Get the SP details for the given environment ID.
	 *
	 * @param string $column The column to return.
	 * @param string $current_environment The current environment.
	 * @return string|array SP details array or single column value.
	 */
	public static function get_sp_details( $column = '', $current_environment = true ) {
		$environment_id = self::get_environment_details( 'id', $current_environment );
		$sp_details     = self::get_records( Constants::DATABASE_TABLE_NAMES['sp_metadata'], array( 'environment_id' => $environment_id ), true );
		if ( ! $sp_details ) {
			return ! empty( $column ) ? '' : array();
		}
		if ( ! $sp_details->sp_entity_id || ! $sp_details->sp_base_url ) {
			$home_url = $current_environment ? home_url() : self::get_environment_details( 'environment_url', $current_environment );

			$sp_details->sp_entity_id = $home_url . Constants::SP_ENTITY_ID;
			$sp_details->sp_base_url  = $home_url;
		}
		return ! empty( $column ) ? $sp_details->$column : $sp_details;
	}

	/**
	 * Get the configured IDP details.
	 *
	 * @param string $column The column to return.
	 * @param bool   $current_environment Whether to return the current environment details. Default is true.
	 * @param bool   $remove_all_idps Whether to remove the 'All IDPs' IDP. Default is false.
	 * @return array The configured IDP details.
	 */
	public static function get_configured_idps_details( $column = '', $current_environment = true, $remove_all_idps = false ) {
		$environment_id = self::get_environment_details( 'id', $current_environment );

		$idp_details = self::get_records( Constants::DATABASE_TABLE_NAMES['idp_details'], array( 'environment_id' => $environment_id ) );
		if ( ! $idp_details ) {
			return array();
		}

		if ( $remove_all_idps || 4 !== MOSAML_VERSION ) {
			$idp_details = array_filter(
				$idp_details,
				function ( $idp ) {
					return 'All IDPs' !== $idp->idp_name;
				}
			);
		}
		if ( ! $column ) {
			return $idp_details;
		}
		return array_reduce(
			$idp_details,
			function ( $carry, $idp ) use ( $column ) {
				if ( isset( $idp->$column ) ) {
					$carry[] = $idp->$column;
				}
				return $carry;
			},
			array()
		);
	}

	/**
	 * Truncates the data from the database tables.
	 *
	 * @param string $table_name The table name.
	 * @return bool True if the data was truncated..
	 */
	public static function truncate_table_data( $table_name = '' ) {
		try {
			if ( empty( $table_name ) ) {
				foreach ( Constants::DATABASE_TABLE_NAMES as $table_key => $table_name ) {
					DB_Queries::instance()->truncate_table_query( $table_name );
				}
			} else {
				DB_Queries::instance()->truncate_table_query( $table_name );
			}
			return true;
		} catch ( Database_Exception $e ) {
			return false;
		}
	}
}
