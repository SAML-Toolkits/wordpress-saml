<?php
/**
 * Table queries class.
 *
 * @package MOSAML\SRC\Database
 */

namespace MOSAML\SRC\Database;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\SRC\Constant\Constants;

/**
 * Table queries class.
 *
 * @package MOSAML\SRC\Database
 */
class Table_Queries {

	/**
	 * The WordPress database object.
	 *
	 * @var wpdb
	 */
	private $wpdb;

	/**
	 * The charset and collation for the database.
	 *
	 * @var string
	 */
	private $charset_collate;

	/**
	 * The prefix for the database tables.
	 *
	 * @var string
	 */
	private $wpdb_prefix;

	/**
	 * The SQL queries for the environments table.
	 *
	 * @var array
	 */
	public $environments_table_query;

	/**
	 * The SQL queries for the IDP details table.
	 *
	 * @var array
	 */
	public $idp_details_table_query;

	/**
	 * The SQL queries for the SP metadata table.
	 *
	 * @var array
	 */
	public $sp_metadata_table_query;

	/**
	 * The SQL queries for the subsites table.
	 *
	 * @var array
	 */
	public $subsites_table_query;

	/**
	 * The SQL queries for the attribute mapping table.
	 *
	 * @var array
	 */
	public $attribute_mapping_table_query;

	/**
	 * The SQL queries for the SSO settings table.
	 *
	 * @var array
	 */
	public $sso_settings_table_query;

	/**
	 * The SQL queries for the role mapping table.
	 *
	 * @var array
	 */
	public $role_mapping_table_query;

	/**
	 * Constructor for the Table_Queries class.
	 */
	public function __construct() {
		global $wpdb;
		$this->wpdb            = $wpdb;
		$this->charset_collate = $this->wpdb->get_charset_collate();
		$this->wpdb_prefix     = $this->wpdb->prefix;

		$this->environments_table_query      = $this->generate_environment_table_query();
		$this->idp_details_table_query       = $this->generate_idp_details_table_query();
		$this->sp_metadata_table_query       = $this->generate_sp_metadata_table_query();
		$this->subsites_table_query          = $this->generate_subsites_table_query();
		$this->attribute_mapping_table_query = $this->generate_attribute_mapping_table_query();
		$this->sso_settings_table_query      = $this->generate_sso_settings_table_query();
		$this->role_mapping_table_query      = $this->generate_role_mapping_table_query();
	}

	/**
	 * Generates the SQL query for the environments table.
	 *
	 * @return array The SQL queries for the environments table.
	 */
	private function generate_environment_table_query() {
		$environments_table = $this->wpdb_prefix . Constants::DATABASE_TABLE_NAMES['environments'];

		$sql['create_table'] = "CREATE TABLE $environments_table (
		id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
		environment_name varchar(100) NOT NULL,
		environment_url varchar(191) NOT NULL,
		selected tinyint(1) DEFAULT 0,
		created_at datetime NOT NULL,
		updated_at datetime NOT NULL,
		PRIMARY KEY (id),
		UNIQUE KEY uk_environment_name (environment_name),
		UNIQUE KEY uk_environment_url (environment_url(100))
        ) $this->charset_collate;";

		return $sql;
	}

	/**
	 * Generates the SQL query for the IDP details table.
	 *
	 * @return array The SQL queries for the IDP details table.
	 */
	private function generate_idp_details_table_query() {
		$idp_details_table = $this->wpdb_prefix . Constants::DATABASE_TABLE_NAMES['idp_details'];

		$sql['create_table'] = "CREATE TABLE $idp_details_table (
			id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
			environment_id bigint(20) unsigned NOT NULL,
			idp_id varchar(45) NOT NULL,
			idp_name varchar(255) NOT NULL,
			entity_id varchar(255) NOT NULL,
			sso_url varchar(255) NOT NULL,
			slo_url varchar(255) DEFAULT NULL,
			idp_certificate text NOT NULL,
			slo_response_url varchar(255) DEFAULT NULL,
			password_reset_url varchar(255) DEFAULT NULL,
			character_encoding varchar(45) DEFAULT NULL,
			assertion_time_validity varchar(45) DEFAULT NULL,
			sign_sso_slo_request varchar(45) DEFAULT NULL,
			sso_binding varchar(100) DEFAULT NULL,
			slo_binding varchar(100) DEFAULT NULL,
			sp_entity_id varchar(255) DEFAULT NULL,
			sync_metadata varchar(45) DEFAULT NULL,
			metadata_url varchar(255) DEFAULT NULL,
			sync_time_interval varchar(45) DEFAULT NULL,
			sync_only_certificate varchar(45) DEFAULT NULL,
			name_id_format varchar(100) NOT NULL,
			default_idp tinyint(1) DEFAULT 0,
			status enum('active', 'inactive') NOT NULL DEFAULT 'active',
			sp_certificate text DEFAULT NULL,
			sp_private_key text DEFAULT NULL,
			test_config_attributes text DEFAULT NULL,
			saml_request text DEFAULT NULL,
			saml_response text DEFAULT NULL,
			created_at datetime NOT NULL,
			updated_at datetime NOT NULL,
			PRIMARY KEY (id),
			KEY environment_id (environment_id),
			KEY idp_id (idp_id)
		) $this->charset_collate;";

		$environments_table = $this->wpdb_prefix . Constants::DATABASE_TABLE_NAMES['environments'];
		$constraint_name    = 'fk_idp_details_environment_id';

		$sql['add_constraint'] = array(
			$constraint_name => "ALTER TABLE {$idp_details_table} 
			ADD CONSTRAINT {$constraint_name} 
			FOREIGN KEY (environment_id) 
			REFERENCES {$environments_table}(id) 
			ON DELETE CASCADE;",
		);

		return $sql;
	}

	/**
	 * Generates the SQL query for the SP metadata table.
	 *
	 * @return array The SQL queries for the SP metadata table.
	 */
	private function generate_sp_metadata_table_query() {
		$default_name  = Constants::DEFAULT_ORGANIZATION_DETAILS['name'];
		$default_email = Constants::DEFAULT_ORGANIZATION_DETAILS['email'];
		$default_url   = Constants::DEFAULT_ORGANIZATION_DETAILS['url'];

		$sp_metadata_table = $this->wpdb_prefix . Constants::DATABASE_TABLE_NAMES['sp_metadata'];

		$sql['create_table'] = "CREATE TABLE $sp_metadata_table (
			id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
			sp_base_url varchar(255) DEFAULT NULL,
			sp_entity_id varchar(255) DEFAULT NULL,
			public_key text DEFAULT NULL,
			private_key text DEFAULT NULL,
			is_custom_certificate tinyint(1) NOT NULL DEFAULT 0,
			organization_name varchar(100) DEFAULT '$default_name',
			organization_display_name varchar(100) DEFAULT '$default_name',
			organization_url varchar(255) DEFAULT '$default_url',
			technical_person_name varchar(100) DEFAULT '$default_name',
			technical_person_email varchar(100) DEFAULT '$default_email',
			support_person_name varchar(100) DEFAULT '$default_name',
			support_person_email varchar(100) DEFAULT '$default_email',
			environment_id bigint(20) unsigned NOT NULL,
			created_at datetime NOT NULL,
			updated_at datetime NOT NULL,
			PRIMARY KEY (id),
			KEY environment_id (environment_id)
		) $this->charset_collate;";

		$environments_table = $this->wpdb_prefix . Constants::DATABASE_TABLE_NAMES['environments'];
		$constraint_name    = 'fk_sp_metadata_environment_id';

		$sql['add_constraint'] = array(
			$constraint_name => "ALTER TABLE {$sp_metadata_table} 
			ADD CONSTRAINT {$constraint_name} 
			FOREIGN KEY (environment_id) 
			REFERENCES {$environments_table}(id) 
			ON DELETE CASCADE;",
		);

		return $sql;
	}

	/**
	 * Generates the SQL query for the subsites table.
	 *
	 * @return array The SQL queries for the subsites table.
	 */
	private function generate_subsites_table_query() {
		$subsites_table = $this->wpdb_prefix . Constants::DATABASE_TABLE_NAMES['subsites'];

		$sql['create_table'] = "CREATE TABLE $subsites_table (
			id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
			blog_id bigint(20) NOT NULL,
			site_url varchar(255) NOT NULL,
			environment_id bigint(20) unsigned NOT NULL,
			created_at datetime NOT NULL,
			updated_at datetime NOT NULL,
			PRIMARY KEY (id),
			KEY environment_id (environment_id)
		) $this->charset_collate;";

		$environments_table = $this->wpdb_prefix . Constants::DATABASE_TABLE_NAMES['environments'];
		$constraint_name    = 'fk_subsites_environment_id';

		$sql['add_constraint'] = array(
			$constraint_name => "ALTER TABLE {$subsites_table} 
			ADD CONSTRAINT {$constraint_name} 
			FOREIGN KEY (environment_id) 
			REFERENCES {$environments_table}(id) 
			ON DELETE CASCADE;",
		);

		return $sql;
	}

	/**
	 * Generates the SQL query for the attribute mapping table.
	 *
	 * @return array The SQL queries for the attribute mapping table.
	 */
	private function generate_attribute_mapping_table_query() {
		$attribute_mapping_table = $this->wpdb_prefix . Constants::DATABASE_TABLE_NAMES['attribute_mapping'];

		$sql['create_table'] = "CREATE TABLE $attribute_mapping_table (
			id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
			option_name varchar(45) NOT NULL,
			option_value varchar(255) DEFAULT NULL,
			custom tinyint(1) NOT NULL DEFAULT 0,
			display tinyint(1) NOT NULL DEFAULT 0,
			idp_id bigint(20) unsigned NOT NULL,
			created_at datetime NOT NULL,
			updated_at datetime NOT NULL,
			PRIMARY KEY (id),
			KEY idp_id (idp_id)
		) $this->charset_collate;";

		$idp_details_table = $this->wpdb_prefix . Constants::DATABASE_TABLE_NAMES['idp_details'];
		$constraint_name   = 'fk_attribute_mapping_idp_id';

		$sql['add_constraint'] = array(
			$constraint_name => "ALTER TABLE {$attribute_mapping_table} 
			ADD CONSTRAINT {$constraint_name} 
			FOREIGN KEY (idp_id) 
			REFERENCES {$idp_details_table}(id) 
			ON DELETE CASCADE;",
		);

		return $sql;
	}

	/**
	 * Generates the SQL query for the SSO settings table.
	 *
	 * @return array The SQL queries for the SSO settings table.
	 */
	private function generate_sso_settings_table_query() {
		$sso_settings_table = $this->wpdb_prefix . Constants::DATABASE_TABLE_NAMES['sso_settings'];

		$sql['create_table'] = "CREATE TABLE $sso_settings_table (
			id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
			option_name varchar(45) NOT NULL,
			option_value varchar(1024) NOT NULL,
			idp_id bigint(20) unsigned NOT NULL,
			subsite_id bigint(20) unsigned NOT NULL,
			created_at datetime NOT NULL,
			updated_at datetime NOT NULL,
			PRIMARY KEY (id),
			KEY idp_id (idp_id),
			KEY subsite_id (subsite_id)
		) $this->charset_collate;";

		$idp_details_table       = $this->wpdb_prefix . Constants::DATABASE_TABLE_NAMES['idp_details'];
		$subsites_table          = $this->wpdb_prefix . Constants::DATABASE_TABLE_NAMES['subsites'];
		$constraint_name_idp     = 'fk_sso_settings_idp_id';
		$constraint_name_subsite = 'fk_sso_settings_subsite_id';

		$sql['add_constraint'] = array(
			$constraint_name_idp     => "ALTER TABLE {$sso_settings_table} 
			ADD CONSTRAINT {$constraint_name_idp} 
			FOREIGN KEY (idp_id) 
			REFERENCES {$idp_details_table}(id) 
			ON DELETE CASCADE;",

			$constraint_name_subsite => "ALTER TABLE {$sso_settings_table} 
			ADD CONSTRAINT {$constraint_name_subsite} 
			FOREIGN KEY (subsite_id) 
			REFERENCES {$subsites_table}(id) 
			ON DELETE CASCADE;",
		);

		return $sql;
	}

	/**
	 * Generates the SQL query for the role mapping table.
	 *
	 * @return array The SQL queries for the role mapping table.
	 */
	private function generate_role_mapping_table_query() {
		$role_mapping_table = $this->wpdb_prefix . Constants::DATABASE_TABLE_NAMES['role_mapping'];

		$sql['create_table'] = "CREATE TABLE $role_mapping_table (
			id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
			role_name varchar(45) NOT NULL,
			idp_group_name varchar(255) DEFAULT NULL,
			idp_id bigint(20) unsigned NOT NULL,
			subsite_id bigint(20) unsigned NOT NULL,
			created_at datetime NOT NULL,
			updated_at datetime NOT NULL,
			PRIMARY KEY (id),
			KEY idp_id (idp_id),
			KEY subsite_id (subsite_id)
		) $this->charset_collate;";

		$idp_details_table       = $this->wpdb_prefix . Constants::DATABASE_TABLE_NAMES['idp_details'];
		$subsites_table          = $this->wpdb_prefix . Constants::DATABASE_TABLE_NAMES['subsites'];
		$constraint_name_idp     = 'fk_role_mapping_idp_id';
		$constraint_name_subsite = 'fk_role_mapping_subsite_id';

		$sql['add_constraint'] = array(
			$constraint_name_idp     => "ALTER TABLE {$role_mapping_table} 
			ADD CONSTRAINT {$constraint_name_idp} 
			FOREIGN KEY (idp_id) 
			REFERENCES {$idp_details_table}(id) 
			ON DELETE CASCADE;",

			$constraint_name_subsite => "ALTER TABLE {$role_mapping_table} 
			ADD CONSTRAINT {$constraint_name_subsite} 
			FOREIGN KEY (subsite_id) 
			REFERENCES {$subsites_table}(id) 
			ON DELETE CASCADE;",
		);

		return $sql;
	}
}
