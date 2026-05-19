<?php
/**
 * Runs semver-named SQL migrations and tracks schema version in the options table ($wpdb->options).
 *
 * @package MOSAML\SRC\Database
 */

namespace MOSAML\SRC\Database;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\SRC\Constant\Constants;
use MOSAML\SRC\Constant\Plugin_Files_Constants;
use MOSAML\SRC\Utils\DB_Utils;
use MOSAML\Traits\Instance;

/**
 * Database migration runner.
 *
 * @package MOSAML\SRC\Database
 */
class Database_Migrator {

	use Instance;

	/**
	 * Cached list of migration files (version => absolute path).
	 *
	 * @var array<string, string>|null
	 */
	private $migration_files;

	/**
	 * WordPress DB handle.
	 *
	 * @var \wpdb
	 */
	private $wpdb;

	/**
	 * Constructor.
	 */
	private function __construct() {
		global $wpdb;
		$this->wpdb = $wpdb;
	}

	/**
	 * Absolute path to the migrations directory.
	 *
	 * @return string
	 */
	public function get_migrations_directory() {
		return trailingslashit( MOSAML_PLUGIN_DIR ) . 'database/migrations/';
	}

	/**
	 * Discover and sort migration files (ascending semver).
	 *
	 * @return array<string, string> Version => file path.
	 */
	public function discover_migration_files() {
		if ( null !== $this->migration_files ) {
			return $this->migration_files;
		}

		$this->migration_files = array();
		$dir                   = $this->get_migrations_directory();
		if ( ! is_dir( $dir ) ) {
			return $this->migration_files;
		}

		$files = glob( $dir . '*.sql' );
		if ( ! is_array( $files ) ) {
			return $this->migration_files;
		}

		foreach ( $files as $file ) {
			$basename = basename( $file, '.sql' );
			if ( ! self::is_valid_semver( $basename ) ) {
				continue;
			}
			$this->migration_files[ $basename ] = $file;
		}

		uksort( $this->migration_files, array( self::class, 'compare_versions' ) );

		return $this->migration_files;
	}

	/**
	 * Whether a string looks like a simple semver (major.minor.patch).
	 *
	 * @param string $version Version string.
	 * @return bool
	 */
	public static function is_valid_semver( $version ) {
		return (bool) preg_match( '/^\d+\.\d+\.\d+$/', $version );
	}

	/**
	 * Compare two semver strings for uksort.
	 *
	 * @param string $a First version.
	 * @param string $b Second version.
	 * @return int
	 */
	public static function compare_versions( $a, $b ) {
		return version_compare( $a, $b );
	}

	/**
	 * Highest migration version present on disk.
	 *
	 * @return string|null Semver or null if none.
	 */
	public static function get_latest_migration_version() {
		$files = self::instance()->discover_migration_files();
		if ( empty( $files ) ) {
			return null;
		}

		$versions = array_keys( $files );
		return $versions[ count( $versions ) - 1 ];
	}

	/**
	 * Normalized applied schema version (same rules as DB_Utils::get_current_db_version()).
	 *
	 * @return string Semver x.y.z, or 0.0.0 when unset.
	 */
	public function get_applied_version() {
		return DB_Utils::get_current_db_version();
	}

	/**
	 * Migration files not yet applied: every file on disk whose version is greater than the applied version, in order, up to get_latest_migration_version().
	 *
	 * Example: applied 0.0.0 and latest 1.0.0 → pending [1.0.0] (runs all SQL through 1.0.0). Applied 1.0.0 and latest 1.0.1 → pending [1.0.1].
	 *
	 * @return string[] Sorted ascending.
	 */
	public function get_pending_migrations() {
		$applied = $this->get_applied_version();
		$pending = array();
		foreach ( array_keys( $this->discover_migration_files() ) as $version ) {
			if ( version_compare( $version, $applied, '>' ) ) {
				$pending[] = $version;
			}
		}
		sort( $pending, SORT_STRING );
		return $pending;
	}

	/**
	 * Legacy installs: tables exist but semver option was never set — assume 1.0.0 schema already applied.
	 *
	 * @return void
	 */
	private function maybe_bootstrap_legacy_version() {
		$stored = get_option( Constants::DB_VERSION_OPTION_NAME, false );
		if ( false !== $stored && '' !== $stored ) {
			return;
		}

		if ( ! $this->all_plugin_tables_exist() ) {
			return;
		}

		update_option( Constants::DB_VERSION_OPTION_NAME, '1.0.0' );
	}

	/**
	 * Whether a table exists in the current database (full name including prefix).
	 *
	 * @param string $table_name Table name.
	 * @return bool
	 */
	private function table_exists( $table_name ) {
		$found = $this->wpdb->get_var(
			$this->wpdb->prepare(
				'SELECT TABLE_NAME FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_SCHEMA = %s AND TABLE_NAME = %s',
				DB_NAME,
				$table_name
			)
		);
		return ! empty( $found );
	}

	/**
	 * Whether all plugin tables exist (names from Constants).
	 *
	 * @return bool
	 */
	private function all_plugin_tables_exist() {
		foreach ( Constants::DATABASE_TABLE_NAMES as $table ) {
			$name = $this->wpdb->prefix . $table;
			if ( ! $this->table_exists( $name ) ) {
				return false;
			}
		}
		return true;
	}

	/**
	 * Run all pending migrations in order. Stops on first failure.
	 *
	 * @return bool True on full success.
	 */
	public function run_migrations() {
		$this->maybe_bootstrap_legacy_version();

		$pending = $this->get_pending_migrations();
		if ( empty( $pending ) ) {
			return true;
		}

		$files = $this->discover_migration_files();

		foreach ( $pending as $version ) {
			if ( empty( $files[ $version ] ) ) {
				continue;
			}

			$contents = file_get_contents( $files[ $version ] );
			if ( false === $contents ) {
				return false;
			}

			$sql = $this->replace_placeholders( $contents );
			if ( ! $this->execute_sql_batch( $sql ) ) {
				return false;
			}

			update_option( Constants::DB_VERSION_OPTION_NAME, $version );
		}

		return true;
	}

	/**
	 * Load WordPress Filesystem API for portable, capability-aware file reads.
	 *
	 * @return \WP_Filesystem_Base|null Global $wp_filesystem instance or null on failure.
	 */
	private function get_wp_filesystem() {
		global $wp_filesystem;

		if ( $wp_filesystem && is_object( $wp_filesystem ) ) {
			return $wp_filesystem;
		}

		if ( ! function_exists( 'WP_Filesystem' ) ) {
			require_once ABSPATH . Plugin_Files_Constants::WP_ADMIN_INCLUDES_FILE;
		}

		if ( ! \WP_Filesystem() || ! $wp_filesystem || ! is_object( $wp_filesystem ) ) {
			return null;
		}

		return $wp_filesystem;
	}

	/**
	 * Replace tokens in migration SQL.
	 *
	 * @param string $sql Raw SQL.
	 * @return string
	 */
	private function replace_placeholders( $sql ) {
		$d = Constants::DEFAULT_ORGANIZATION_DETAILS;
		return str_replace(
			array(
				'{prefix}',
				'{charset_collate}',
				'{default_org_name}',
				'{default_org_email}',
				'{default_org_url}',
			),
			array(
				$this->wpdb->prefix,
				$this->wpdb->get_charset_collate(),
				esc_sql( $d['name'] ),
				esc_sql( $d['email'] ),
				esc_sql( $d['url'] ),
			),
			$sql
		);
	}

	/**
	 * Strip SQL comments and split on semicolons (migrations must not put semicolons inside string literals).
	 *
	 * @param string $sql SQL text.
	 * @return string[] Non-empty statements.
	 */
	private function split_sql_statements( $sql ) {
		$sql = preg_replace( '/^\s*--.*$/m', '', $sql );
		$sql = preg_replace( '/\/\*[\s\S]*?\*\//', '', $sql );

		$parts  = explode( ';', $sql );
		$out    = array();
		foreach ( $parts as $part ) {
			$part = trim( $part );
			if ( '' !== $part ) {
				$out[] = $part;
			}
		}
		return $out;
	}

	/**
	 * Execute all statements; optional guard for ALTER MODIFY on missing columns.
	 *
	 * @param string $sql Full file SQL.
	 * @return bool
	 */
	private function execute_sql_batch( $sql ) {
		$statements = $this->split_sql_statements( $sql );
		foreach ( $statements as $statement ) {
			if ( ! $this->execute_statement( $statement ) ) {
				return false;
			}
		}
		return true;
	}

	/**
	 * Run one SQL statement with error handling and idempotent FK adds.
	 *
	 * @param string $statement SQL.
	 * @return bool
	 */
	private function execute_statement( $statement ) {
		$trimmed = ltrim( $statement );
		if ( 0 === stripos( $trimmed, 'ALTER TABLE' ) && false !== stripos( $trimmed, 'ADD CONSTRAINT' ) ) {
			return $this->execute_add_constraint_if_missing( $statement );
		}

		if ( 0 === stripos( $trimmed, 'ALTER TABLE' ) && false !== stripos( $trimmed, 'MODIFY' ) ) {
			return $this->execute_modify_column_if_present( $statement );
		}

		// phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared -- Migration SQL is bundled with the plugin.
		$result = $this->wpdb->query( $statement );
		if ( false === $result && ! empty( $this->wpdb->last_error ) ) {
			return false;
		}
		return true;
	}

	/**
	 * ADD CONSTRAINT only when the constraint is not already present.
	 *
	 * @param string $statement Full ALTER TABLE ... ADD CONSTRAINT ...
	 * @return bool
	 */
	private function execute_add_constraint_if_missing( $statement ) {
		if ( ! preg_match( '/ADD\s+CONSTRAINT\s+`?([A-Za-z0-9_]+)`?/i', $statement, $cm ) ) {
			// phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
			$result = $this->wpdb->query( $statement );
			return false !== $result || empty( $this->wpdb->last_error );
		}
		$constraint_name = $cm[1];

		if ( ! preg_match( '/ALTER\s+TABLE\s+`?([A-Za-z0-9_]+)`?/i', $statement, $tm ) ) {
			return false;
		}
		$table_name = $tm[1];

		$exists = (int) $this->wpdb->get_var(
			$this->wpdb->prepare(
				'SELECT COUNT(*) FROM INFORMATION_SCHEMA.TABLE_CONSTRAINTS WHERE CONSTRAINT_SCHEMA = %s AND TABLE_NAME = %s AND CONSTRAINT_NAME = %s',
				DB_NAME,
				$table_name,
				$constraint_name
			)
		);

		if ( $exists > 0 ) {
			return true;
		}

		// phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
		$result = $this->wpdb->query( $statement );
		if ( false === $result && ! empty( $this->wpdb->last_error ) ) {
			return false;
		}
		return true;
	}

	/**
	 * MODIFY COLUMN only if the column exists (avoids hard failure on partial installs).
	 *
	 * @param string $statement ALTER TABLE ... MODIFY ...
	 * @return bool
	 */
	private function execute_modify_column_if_present( $statement ) {
		if ( ! preg_match( '/ALTER\s+TABLE\s+`?([A-Za-z0-9_]+)`?/i', $statement, $tm ) ) {
			return false;
		}
		$table = $tm[1];

		if ( ! preg_match( '/MODIFY(?:\s+COLUMN)?\s+`?([A-Za-z0-9_]+)`?/i', $statement, $cm ) ) {
			return false;
		}
		$column = $cm[1];

		$col_exists = (int) $this->wpdb->get_var(
			$this->wpdb->prepare(
				'SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA = %s AND TABLE_NAME = %s AND COLUMN_NAME = %s',
				DB_NAME,
				$table,
				$column
			)
		);

		if ( $col_exists < 1 ) {
			return true;
		}

		// phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
		$result = $this->wpdb->query( $statement );
		if ( false === $result && ! empty( $this->wpdb->last_error ) ) {
			return false;
		}
		return true;
	}
}
