-- Remove automatic timestamp defaults; application sets created_at / updated_at explicitly.

ALTER TABLE `{prefix}mosaml_environments` MODIFY COLUMN `created_at` DATETIME NOT NULL;
ALTER TABLE `{prefix}mosaml_environments` MODIFY COLUMN `updated_at` DATETIME NOT NULL;

ALTER TABLE `{prefix}mosaml_idp_details` MODIFY COLUMN `created_at` DATETIME NOT NULL;
ALTER TABLE `{prefix}mosaml_idp_details` MODIFY COLUMN `updated_at` DATETIME NOT NULL;

ALTER TABLE `{prefix}mosaml_sp_metadata` MODIFY COLUMN `created_at` DATETIME NOT NULL;
ALTER TABLE `{prefix}mosaml_sp_metadata` MODIFY COLUMN `updated_at` DATETIME NOT NULL;

ALTER TABLE `{prefix}mosaml_subsites` MODIFY COLUMN `created_at` DATETIME NOT NULL;
ALTER TABLE `{prefix}mosaml_subsites` MODIFY COLUMN `updated_at` DATETIME NOT NULL;

ALTER TABLE `{prefix}mosaml_attribute_mapping` MODIFY COLUMN `created_at` DATETIME NOT NULL;
ALTER TABLE `{prefix}mosaml_attribute_mapping` MODIFY COLUMN `updated_at` DATETIME NOT NULL;

ALTER TABLE `{prefix}mosaml_sso_settings` MODIFY COLUMN `created_at` DATETIME NOT NULL;
ALTER TABLE `{prefix}mosaml_sso_settings` MODIFY COLUMN `updated_at` DATETIME NOT NULL;

ALTER TABLE `{prefix}mosaml_role_mapping` MODIFY COLUMN `created_at` DATETIME NOT NULL;
ALTER TABLE `{prefix}mosaml_role_mapping` MODIFY COLUMN `updated_at` DATETIME NOT NULL;
