-- Initial schema (matches legacy Table_Queries; timestamp defaults adjusted in 1.0.1.sql).

CREATE TABLE IF NOT EXISTS `{prefix}mosaml_environments` (
	id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
	environment_name varchar(100) NOT NULL,
	environment_url varchar(191) NOT NULL,
	selected tinyint(1) DEFAULT 0,
	created_at datetime NOT NULL,
	updated_at datetime NOT NULL,
	PRIMARY KEY (id),
	UNIQUE KEY uk_environment_name (environment_name),
	UNIQUE KEY uk_environment_url (environment_url(100))
) {charset_collate};

CREATE TABLE IF NOT EXISTS `{prefix}mosaml_idp_details` (
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
) {charset_collate};

CREATE TABLE IF NOT EXISTS `{prefix}mosaml_sp_metadata` (
	id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
	sp_base_url varchar(255) DEFAULT NULL,
	sp_entity_id varchar(255) DEFAULT NULL,
	public_key text DEFAULT NULL,
	private_key text DEFAULT NULL,
	is_custom_certificate tinyint(1) NOT NULL DEFAULT 0,
	organization_name varchar(100) DEFAULT '{default_org_name}',
	organization_display_name varchar(100) DEFAULT '{default_org_name}',
	organization_url varchar(255) DEFAULT '{default_org_url}',
	technical_person_name varchar(100) DEFAULT '{default_org_name}',
	technical_person_email varchar(100) DEFAULT '{default_org_email}',
	support_person_name varchar(100) DEFAULT '{default_org_name}',
	support_person_email varchar(100) DEFAULT '{default_org_email}',
	environment_id bigint(20) unsigned NOT NULL,
	created_at datetime NOT NULL,
	updated_at datetime NOT NULL,
	PRIMARY KEY (id),
	KEY environment_id (environment_id)
) {charset_collate};

CREATE TABLE IF NOT EXISTS `{prefix}mosaml_subsites` (
	id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
	blog_id bigint(20) NOT NULL,
	site_url varchar(255) NOT NULL,
	environment_id bigint(20) unsigned NOT NULL,
	created_at datetime NOT NULL,
	updated_at datetime NOT NULL,
	PRIMARY KEY (id),
	KEY environment_id (environment_id)
) {charset_collate};

CREATE TABLE IF NOT EXISTS `{prefix}mosaml_attribute_mapping` (
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
) {charset_collate};

CREATE TABLE IF NOT EXISTS `{prefix}mosaml_role_mapping` (
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
) {charset_collate};

CREATE TABLE IF NOT EXISTS `{prefix}mosaml_sso_settings` (
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
) {charset_collate};

ALTER TABLE `{prefix}mosaml_idp_details`
ADD CONSTRAINT `fk_idp_details_environment_id`
FOREIGN KEY (environment_id)
REFERENCES `{prefix}mosaml_environments`(id)
ON DELETE CASCADE;

ALTER TABLE `{prefix}mosaml_sp_metadata`
ADD CONSTRAINT `fk_sp_metadata_environment_id`
FOREIGN KEY (environment_id)
REFERENCES `{prefix}mosaml_environments`(id)
ON DELETE CASCADE;

ALTER TABLE `{prefix}mosaml_subsites`
ADD CONSTRAINT `fk_subsites_environment_id`
FOREIGN KEY (environment_id)
REFERENCES `{prefix}mosaml_environments`(id)
ON DELETE CASCADE;

ALTER TABLE `{prefix}mosaml_attribute_mapping`
ADD CONSTRAINT `fk_attribute_mapping_idp_id`
FOREIGN KEY (idp_id)
REFERENCES `{prefix}mosaml_idp_details`(id)
ON DELETE CASCADE;

ALTER TABLE `{prefix}mosaml_sso_settings`
ADD CONSTRAINT `fk_sso_settings_idp_id`
FOREIGN KEY (idp_id)
REFERENCES `{prefix}mosaml_idp_details`(id)
ON DELETE CASCADE;

ALTER TABLE `{prefix}mosaml_sso_settings`
ADD CONSTRAINT `fk_sso_settings_subsite_id`
FOREIGN KEY (subsite_id)
REFERENCES `{prefix}mosaml_subsites`(id)
ON DELETE CASCADE;

ALTER TABLE `{prefix}mosaml_role_mapping`
ADD CONSTRAINT `fk_role_mapping_idp_id`
FOREIGN KEY (idp_id)
REFERENCES `{prefix}mosaml_idp_details`(id)
ON DELETE CASCADE;

ALTER TABLE `{prefix}mosaml_role_mapping`
ADD CONSTRAINT `fk_role_mapping_subsite_id`
FOREIGN KEY (subsite_id)
REFERENCES `{prefix}mosaml_subsites`(id)
ON DELETE CASCADE;
