<?php
/**
 * This file contains all the queries to create, update, read, and delete tables.
 *
 * @package    MOSAML
 * @subpackage MOSAML/src/database
 */

namespace MOSAML\SRC\Database;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use wpdb;
use MOSAML\Traits\Instance;
use MOSAML\SRC\Constant\Constants;
use MOSAML\SRC\Exception\Database_Exception;

/**
 * Database queries class.
 *
 * @package MOSAML\SRC\Database
 */
class DB_Queries {

	use Instance;

	/**
	 * The WordPress database object.
	 *
	 * @var wpdb
	 */
	private $wpdb;

	/**
	 * The prefix for the database tables.
	 *
	 * @var string
	 */
	private $prefix;

	/**
	 * Constructor for the DB_Queries class.
	 */
	public function __construct() {
		global $wpdb;
		$this->wpdb   = $wpdb;
		$this->prefix = $this->wpdb->prefix;
	}

	/**
	 * Prepares and runs a query with the given table name and values.
	 *
	 * @param string $action The action to perform.
	 * @param string $table_name The table name without prefix.
	 * @param array  $data The data to insert or update.
	 * @param array  $where The where clause.
	 * @param string $where_operator The operator to use for the where clause.
	 * @param string $in_clause_key The key for the in clause.
	 * @param array  $in_clause_value The value for the in clause.
	 * @param string $in_clause_type The type of in clause.
	 * @param string $in_clause_operator The operator to use for the in clause.
	 * @return int|false The number of rows affected or false on failure.
	 *
	 * @throws \Exception If the action is not supported.
	 */
	public function prepare_and_run_query( $action, $table_name, $data, $where, $where_operator = 'AND', $in_clause_key = '', $in_clause_value = array(), $in_clause_type = 'IN', $in_clause_operator = 'AND' ) {
		$table_name = $this->prefix . esc_sql( $table_name );
		$action     = strtoupper( trim( $action ) );
		$query      = '';

		switch ( $action ) {
			case 'INSERT':
				$columns = implode( ',', array_map( 'esc_sql', array_keys( $data ) ) );
				$values  = implode(
					',',
					array_map(
						function ( $val ) {
							return "'" . esc_sql( $val ) . "'";
						},
						$data
					)
				);
				$query   = "INSERT INTO {$table_name} ({$columns}) VALUES ({$values})";
				break;

			case 'UPDATE':
				$set = implode(
					',',
					array_map(
						function ( $col, $val ) {
							return esc_sql( $col ) . "='" . esc_sql( $val ) . "'";
						},
						array_keys( $data ),
						$data
					)
				);

				$query = "UPDATE {$table_name} SET {$set}";
				$query = $this->generate_and_add_where_clause( $query, $where, $where_operator );
				$query = $this->generate_and_add_in_clause( $query, $in_clause_key, $in_clause_value, $in_clause_type, $in_clause_operator );
				break;

			case 'DELETE':
				$query = "DELETE FROM {$table_name}";
				$query = $this->generate_and_add_where_clause( $query, $where, $where_operator );
				$query = $this->generate_and_add_in_clause( $query, $in_clause_key, $in_clause_value, $in_clause_type, $in_clause_operator );
				break;

			case 'SELECT':
			case 'GET':
				$query = "SELECT * FROM {$table_name}";
				$query = $this->generate_and_add_where_clause( $query, $where, $where_operator );
				$query = $this->generate_and_add_in_clause( $query, $in_clause_key, $in_clause_value, $in_clause_type, $in_clause_operator );
				break;

			default:
				throw new \Exception( esc_html( "Unsupported action: {$action}" ) );
		}

		// phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery, PluginCheck.Security.DirectDB.UnescapedDBParameter
		return $this->wpdb->query( $query );
	}

	/**
	 * Inserts or updates a row in the database.
	 *
	 * @param string $table The table name.
	 * @param array  $data The data to insert or update.
	 * @param array  $where The where clause.
	 * @param string $operator The operator to use for the where clause.
	 * @param bool   $return_id Whether to return the id of the inserted row.
	 *
	 * @return int|false The id of the inserted row or false on failure.
	 */
	public function insert_or_update_query( $table, $data, $where, $operator = 'AND', $return_id = false ) {
		if ( ! $this->table_exists_query( $table ) ) {
			return false;
		}

		$table = $this->prefix . $table;
		$sql   = "SELECT id FROM `$table`";

		$sql = $this->generate_and_add_where_clause( $sql, $where, $operator );

		// phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter -- $this-wpdb is the copy of global $wpdb and the sql is manually prepared with proper sanitization.
		$existing_record = $this->wpdb->get_var( $sql );

		$data = array_map( 'maybe_serialize', $data );

		$affected_rows = 0;
		if ( $existing_record ) {
			$data['updated_at'] = current_time( 'mysql' );
			$affected_rows = $this->wpdb->update( $table, $data, $where );
		} else {
			$data['created_at'] = current_time( 'mysql' );
			$data['updated_at'] = current_time( 'mysql' );
			$affected_rows = $this->wpdb->insert( $table, $data );
		}

		if ( $affected_rows && $return_id ) {
			return $this->wpdb->insert_id;
		} elseif ( $affected_rows ) {
			return true;
		}
		return false;
	}

	/**
	 * Generate and add a WHERE clause for $wpdb queries.
	 *
	 * @param string $sql The SQL query.
	 * @param array  $where Key-value pairs where key is column and value is the value to match.
	 * @param string $operator   Logical operator to join conditions (default 'AND').
	 * @param string $predicate The predicate to use for the where clause.
	 *
	 * @return string The SQL query with the WHERE clause.
	 */
	private function generate_and_add_where_clause( $sql, $where, $operator = 'AND', $predicate = '=' ) {
		if ( empty( $where ) ) {
			return $sql;
		}

		$clauses = array();
		$values  = array();

		foreach ( $where as $column => $value ) {
			if ( is_array( $value ) ) {
				$_predicate = '=' === $predicate ? 'IN' : $predicate;
				$clauses[]  = '`' . $column . '` ' . $_predicate . ' (' . implode( ',', array_fill( 0, count( $value ), '%s' ) ) . ')';
				foreach ( $value as $v ) {
					$values[] = $v;
				}
			} else {
				$clauses[] = '`' . $column . '` ' . $predicate . ' %s';
				if ( 'LIKE' === strtoupper( $predicate ) ) {
					$values[] = '%' . $this->wpdb->esc_like( $value ) . '%';
				} else {
					$values[] = $value;
				}
			}
		}

		$where_sql = implode( " $operator ", $clauses );
		$sql      .= " WHERE $where_sql";
		// phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared -- $this-wpdb is the copy of global $wpdb and the sql is manually prepared with proper sanitization.
		return $this->wpdb->prepare( $sql, ...$values );
	}

	/**
	 * Generate and add an IN clause for $wpdb queries.
	 *
	 * @param string $sql The SQL query.
	 * @param string $in_clause_key The key for the in clause.
	 * @param array  $in_clause_value The value for the in clause.
	 * @param string $in_clause_type The type of in clause.
	 * @param string $in_clause_operator The operator to use for the in clause.
	 * @return string The SQL query with the IN clause.
	 */
	private function generate_and_add_in_clause( $sql, $in_clause_key, $in_clause_value, $in_clause_type, $in_clause_operator = 'AND' ) {
		if ( empty( $in_clause_key ) || empty( $in_clause_value ) ) {
			return $sql;
		}

		$sql .= ' ' . $in_clause_operator . ' ' . $in_clause_key . ' ' . $in_clause_type . ' (' . implode( ',', array_fill( 0, count( $in_clause_value ), '%s' ) ) . ')';
		// phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared -- $this-wpdb is the copy of global $wpdb and the sql is manually prepared with proper sanitization.
		return $this->wpdb->prepare( $sql, $in_clause_value );
	}

	/**
	 * Deletes a row from the database.
	 *
	 * @param string $table The table name.
	 * @param array  $where The where clause.
	 * @return int The number of rows affected.
	 */
	public function delete_query( $table, $where ) {
		if ( ! $this->table_exists_query( $table ) ) {
			return 0;
		}

		$this->wpdb->delete( $this->prefix . $table, $where );
		return $this->wpdb->rows_affected;
	}

	/**
	 * Drops a table from the database.
	 *
	 * @param string $table The table name.
	 * @return bool True if the table was dropped or not found.
	 */
	public function drop_query( $table ) {
		if ( ! $this->table_exists_query( $table ) ) {
			return true;
		}

		$table_name = $this->prefix . $table;

		$sql = "DROP TABLE IF EXISTS `$table_name`";
		// phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery, PluginCheck.Security.DirectDB.UnescapedDBParameter -- $this->wpdb is the copy of global $wpdb and the sql is manually prepared with proper sanitization.
		return $this->wpdb->query( $sql );
	}

	/**
	 * Checks if a table exists in the database.
	 *
	 * @param string $table The table name.
	 * @return string|null The table name if it exists.
	 */
	public function table_exists_query( $table ) {
		$table_name = $this->prefix . $table;

		$sql = $this->wpdb->prepare(
			'SELECT TABLE_NAME
			FROM INFORMATION_SCHEMA.TABLES
			WHERE TABLE_SCHEMA = %s
			AND TABLE_NAME = %s',
			array(
				DB_NAME,
				$table_name,
			)
		);
		// phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared -- Already used wpdb::prepare().
		return $this->wpdb->get_var( $sql );
	}

	/**
	 * Get multiple records from the database.
	 *
	 * @param string $table The table name.
	 * @param array  $where The where clause.
	 * @param string $operator The operator to use for the where clause.
	 * @param bool   $single_record Whether to return a single record or multiple records.
	 * @param string $order_by The order by clause.
	 * @param string $order The order direction.
	 * @param array  $columns The columns to fetch.
	 * @param string $predicate The predicate to use for the where clause.
	 * @return object|array|null|void The record object or array of record objects or null or void if no records are found or table not found.
	 */
	public function get_query( $table, $where, $operator = 'AND', $single_record = false, $order_by = '', $order = 'ASC', $columns = array( '*' ), $predicate = '=' ) {
		if ( ! $this->table_exists_query( $table ) ) {
			return null;
		}

		$table   = $this->prefix . $table;
		$columns = $this->build_columns( $columns );
		$sql     = "SELECT $columns FROM $table";

		$sql = $this->generate_and_add_where_clause( $sql, $where, $operator, $predicate );

		$sql .= $this->generate_order_by( $order_by, $order );
		// phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery, PluginCheck.Security.DirectDB.UnescapedDBParameter -- $this->wpdb is the copy of global $wpdb and the sql is manually prepared with proper sanitization.
		return $single_record ? $this->wpdb->get_row( $sql ) : $this->wpdb->get_results( $sql );
	}

	/**
	 * Truncates a table in the database.
	 *
	 * @param string $table The table name.
	 * @return bool True if the table was truncated or not found.
	 * @throws Database_Exception If the table is not found.
	 */
	public function truncate_table_query( $table ) {
		$this->wpdb->query( 'SET FOREIGN_KEY_CHECKS = 0' );
		if ( ! $this->table_exists_query( $table ) ) {
			throw new Database_Exception( 'Table not found: ' . esc_html( $table ) );
		}

		$table = $this->prefix . $table;
		$sql   = "TRUNCATE TABLE $table";

		// phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery, PluginCheck.Security.DirectDB.UnescapedDBParameter -- $this->wpdb is the copy of global $wpdb and the sql is manually prepared with proper sanitization.
		$result = $this->wpdb->query( $sql );
		$this->wpdb->query( 'SET FOREIGN_KEY_CHECKS = 1' );
		return $result ? true : false;
	}

	/**
	 * Build columns part of SELECT query.
	 *
	 * @param array $columns Array of column names, default ['*'].
	 *
	 * @return string Columns SQL string
	 */
	private function build_columns( $columns = array( '*' ) ) {
		return implode(
			', ',
			array_map(
				function ( $col ) {
					return "$col";
				},
				$columns
			)
		);
	}

	/**
	 * Generate ORDER BY clause.
	 *
	 * @param string $order_by Column to order by.
	 * @param string $order    Direction ASC or DESC.
	 *
	 * @return string ORDER BY SQL string
	 */
	private function generate_order_by( $order_by = '', $order = 'ASC' ) {
		if ( empty( $order_by ) ) {
			return '';
		}

		$order = strtoupper( $order ) === 'DESC' ? 'DESC' : 'ASC';
		return " ORDER BY `$order_by` $order";
	}
}
