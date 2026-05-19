# Plugin Architecture: miniOrange SAML 2.0 SSO

This document provides a comprehensive overview of the plugin architecture, including directory structure, file organization, component responsibilities, security architecture, and development workflow.

## Table of Contents

1. [Plugin Overview](#plugin-overview)
2. [Directory Structure](#directory-structure)
3. [Core Components](#core-components)
4. [Module System](#module-system)
5. [Database Architecture](#database-architecture)
6. [Security Architecture](#security-architecture)
7. [Code Quality & Standards](#code-quality--standards)
8. [Development Workflow](#development-workflow)

## Plugin Overview

**Plugin Name**: miniOrange SAML SSO  
**Plugin Slug**: `miniorange-saml-20-single-sign-on`  
**Namespace**: `MOSAML`  
**Text Domain**: `miniorange-saml-20-single-sign-on`  
**Main File**: `login.php`  
**Version**: 1.0.0

### Plugin Initialization Flow

1. **Main Plugin File** (`login.php`):
   - Defines plugin constants (`MOSAML_PLUGIN_DIR`, `MOSAML_PLUGIN_FILE`, `MOSAML_VERSION`)
   - Registers autoloader function
   - Loads integration functions and libraries
   - Instantiates `SAML_MO_Login` class

2. **Autoloader** (`autoloader.php`):
   - Converts namespace to file path
   - Automatically loads classes based on namespace structure
   - Pattern: `MOSAML\SRC\Controller\Init_Controller` → `src/controller/class-init-controller.php`

3. **Hook Registration** (`src/hook/class-register-hooks.php`):
   - Registers all WordPress hooks (actions and filters)
   - Sets up activation/deactivation hooks
   - Registers admin menu and page hooks

## Directory Structure

### Root Level Files

```
miniorange-saml-20-single-sign-on/
├── login.php                    # Main plugin file - entry point
├── autoloader.php               # Class autoloader function
├── uninstall.php                # Plugin uninstall handler
├── .cursorrules                 # Development guidelines and rules
└── docs/                        # Documentation directory
    ├── ARCHITECTURE.md          # This file - plugin architecture
    └── instructions.md           # Plugin-specific instructions
```

### Core Source Directory (`src/`)

The `src/` directory contains all core functionality shared across all plugin versions.

```
src/
├── abstract/                    # Abstract base classes
│   ├── class-hook-gate-keeper.php
│   └── index.php
├── classes/                     # Utility and helper classes
│   ├── class-debug-logger.php   # Debug logging functionality
│   ├── class-metadata-reader.php # SAML metadata parsing
│   ├── class-mo-customer.php    # Customer/license management
│   └── index.php
├── config/                      # Configuration handlers
│   ├── class-import-config-handler.php
│   └── index.php
├── constant/                    # Constants and enums
│   ├── class-constants.php      # Plugin constants (tabs, tables, versions)
│   ├── class-error-codes-enums.php # Error code definitions
│   ├── class-plugin-files-constants.php # File path constants
│   ├── class-plugin-options.php # WordPress options constants
│   ├── class-xml-constants.php  # XML/SAML constants
│   └── index.php
├── controller/                  # Request controllers (MVC pattern)
│   ├── class-admin-init-controller.php # Admin form submissions
│   ├── class-init-controller.php # Public SAML requests
│   ├── class-logout-controller.php # SAML logout handling
│   ├── class-menu-page-controller.php # Admin menu pages
│   └── index.php
├── database/                    # Database operations
│   ├── class-cache-handler.php  # Database query caching
│   ├── class-db-queries.php     # Database CRUD operations
│   ├── class-table-queries.php # Table creation queries
│   └── index.php
├── dto/                         # Data Transfer Objects
│   ├── class-assertions-dto.php # SAML assertion data
│   ├── class-saml-request-dto.php # SAML request data
│   ├── class-saml-response-dto.php # SAML response data
│   ├── class-user-attributes-dto.php # User attribute data
│   └── index.php
├── entity/                      # Entity classes
│   ├── class-idp-details.php    # IdP details entity
│   └── index.php
├── exception/                   # Custom exception classes
│   ├── class-invalid-assertion-exception.php
│   ├── class-invalid-xml-exception.php
│   ├── class-signature-not-found-exception.php
│   ├── class-metadata-validation-exception.php
│   └── [20+ more exception classes]
│   └── index.php
├── handler/                     # Business logic handlers
│   ├── class-database-cleanup-handler.php
│   ├── class-exception-handler.php
│   ├── class-license-expiry-page-handler.php
│   ├── core/                    # Core handlers
│   │   ├── class-user-login-handler.php
│   │   └── index.php
│   ├── import-export/          # Import/export functionality
│   │   ├── class-import-config-handler.php
│   │   ├── class-import-export-config-handler.php
│   │   └── version-mappings/   # Version-specific mappings
│   ├── migration/               # Legacy data migration
│   │   ├── class-legacy-migration-handler.php
│   │   ├── class-legacy-options-service.php
│   │   └── version-mappings/
│   ├── ui/                      # UI rendering handlers
│   │   ├── class-account-settings-ui-handler.php
│   │   ├── class-advanced-settings-ui-handler.php
│   │   ├── class-attribute-role-mapping-ui-handler.php
│   │   ├── class-sp-metadata-ui-handler.php
│   │   ├── class-sp-setup-ui-handler.php
│   │   └── [8+ more UI handlers]
│   └── index.php
├── hook/                        # WordPress hooks
│   ├── class-hooks-action.php   # Hook action callbacks
│   ├── class-register-hooks.php # Hook registration
│   └── index.php
├── integration/                 # Integration functions
│   └── integration-functions.php
├── interfaces/                  # Interface definitions
│   └── [4 interface files]
├── library/                     # Third-party libraries
│   ├── license/                 # License management library
│   │   └── [49 files]
│   ├── robrichards/            # XMLSecLibs for SAML
│   │   └── [15 files]
│   └── index.php
├── migration/                   # Data migration system
│   ├── abstract/
│   │   └── class-abstract-data-mapping.php
│   ├── helper/
│   │   └── class-data-transformer.php
│   └── module/
│       └── enterprise/
│           └── class-environment-data-mapping.php
├── template/                    # Admin page templates
│   └── [57 template files]
├── utils/                       # Utility functions
│   ├── class-certificate-utility.php
│   ├── class-db-utils.php      # Database utilities
│   ├── class-error-success-message.php
│   ├── class-feature-control.php # License/feature checking
│   ├── class-utility.php        # General utilities
│   ├── class-xml-utility.php    # XML processing utilities
│   └── index.php
└── index.php
```

### Module System (`module/`)

The plugin uses a modular architecture to support different versions (Base, Standard, Premium, Enterprise).

```
module/
├── base/                        # Base version (free) - common functionality
│   ├── config/                  # Base configuration handlers
│   ├── exception/               # Base exception classes
│   ├── handler/                # Base handlers
│   │   ├── admin/              # Admin form handlers
│   │   └── saml/               # SAML request/response handlers
│   └── index.php
├── standard/                    # Standard version features
│   ├── config/
│   ├── exception/
│   ├── handler/
│   │   ├── admin/
│   │   └── saml/
│   └── index.php
├── premium/                     # Premium version features
│   ├── cli/                     # CLI commands
│   ├── config/
│   ├── exception/
│   ├── handler/
│   │   ├── admin/
│   │   └── saml/
│   ├── template/
│   └── index.php
└── enterprise/                  # Enterprise version features
    ├── config/
    ├── exception/
    ├── handler/
    │   ├── admin/
    │   └── saml/
    └── index.php
```

**Version Detection**:
- Version is determined by checking which module directories exist
- `MOSAML_VERSION` constant: 1 = BASE, 2 = STANDARD, 3 = PREMIUM, 4 = ENTERPRISE
- Handlers are resolved based on version (version-specific → base fallback)

### Static Assets (`static/`)

```
static/
├── css/                         # Stylesheets
│   └── [12 CSS files]
├── js/                          # JavaScript files
│   └── [14 JS files]
├── image/                       # Images
│   └── [55 image files]
├── resource/                    # Resource files (certificates, keys)
│   └── [3 files - protected by .htaccess]
└── index.php
```

### Other Directories

```
traits/                          # PHP traits
├── class-instance.php           # Singleton trait
└── index.php

resource/                        # Additional resources
└── index.php
```

## Core Components

### 1. Controllers (`src/controller/`)

Controllers handle incoming requests and delegate to appropriate handlers.

- **`Init_Controller`**: Handles public-facing SAML requests (authentication, response processing)
- **`Admin_Init_Controller`**: Handles admin form submissions and AJAX requests
- **`Logout_Controller`**: Handles SAML logout requests
- **`Menu_Page_Controller`**: Renders admin menu pages and tabs

### 2. Handlers (`src/handler/` and `module/*/handler/`)

Handlers contain business logic organized by type:

#### Core Handlers (`src/handler/core/`)
- **`User_Login_Handler`**: Creates/updates WordPress users from SAML attributes

#### Admin Handlers (`module/*/handler/admin/`)
- **`SP_Setup_Data_Handler`**: Handles IdP configuration form submissions
- **`Attribute_Mapping_Data_Handler`**: Handles attribute mapping configuration
- **`Role_Mapping_Data_Handler`**: Handles role mapping configuration
- **`Advanced_Settings_Data_Handler`**: Handles advanced settings
- **`SSO_Redirection_Settings_Data_Handler`**: Handles SSO redirection settings

#### SAML Handlers (`module/*/handler/saml/`)
- **`SAML_Request_Handler`**: Generates and sends SAML authentication requests
- **`SAML_Response_Handler`**: Processes SAML responses and assertions
- **`SAML_Logout_Handler`**: Handles SAML logout requests/responses

#### UI Handlers (`src/handler/ui/`)
- **`SP_Metadata_UI_Handler`**: Renders Service Provider metadata page
- **`SP_Setup_UI_Handler`**: Renders IdP configuration page
- **`Attribute_Role_Mapping_UI_Handler`**: Renders attribute/role mapping page
- **`Advanced_Settings_UI_Handler`**: Renders advanced settings page
- **`Account_Settings_UI_Handler`**: Renders account settings page

### 3. Data Transfer Objects (`src/dto/`)

DTOs encapsulate data structures for SAML operations:

- **`SAML_Request_DTO`**: Contains SAML authentication request data
- **`SAML_Response_DTO`**: Contains SAML response data
- **`Assertions_DTO`**: Contains SAML assertion data
- **`User_Attributes_DTO`**: Contains user attribute data from SAML

### 4. Utilities (`src/utils/`)

- **`Utility`**: General utility functions (sanitization, handler resolution, user lookup)
- **`DB_Utils`**: Database utility functions (table creation, initialization)
- **`Certificate_Utility`**: Certificate processing and validation
- **`XML_Utility`**: XML parsing and processing utilities
- **`Feature_Control`**: License and feature checking
- **`Error_Success_Message`**: Error/success message display

### 5. Constants (`src/constant/`)

- **`Constants`**: Plugin constants (tabs, database tables, versions, required extensions)
- **`Error_Codes_Enums`**: Error code definitions and messages
- **`Plugin_Options`**: WordPress options names
- **`Plugin_Files_Constants`**: File path constants
- **`XML_Constants`**: XML/SAML namespace and element constants

### 6. Database Layer (`src/database/`)

- **`DB_Queries`**: Database CRUD operations using `$wpdb`
- **`Table_Queries`**: SQL queries for table creation
- **`Cache_Handler`**: Database query result caching

### 7. Exception Handling (`src/exception/`)

Custom exception classes for SAML-specific errors:
- `Invalid_Assertion_Exception`
- `Invalid_XML_Exception`
- `Signature_Not_Found_Exception`
- `Metadata_Validation_Exception`
- `Invalid_Audience_URI_Exception`
- `Encrypted_Assertion_Exception`
- And 20+ more specialized exceptions

## Module System

### Version Hierarchy

1. **BASE (Version 1)**: Free version with basic SAML SSO
2. **STANDARD (Version 2)**: Standard features
3. **PREMIUM (Version 3)**: Premium features
4. **ENTERPRISE (Version 4)**: Enterprise features

### Handler Resolution

Handlers are resolved using `Utility::get_handler_object()`:

1. Check if version-specific handler exists in `module/{version}/handler/{type}/`
2. Fall back to base handler in `module/base/handler/{type}/`
3. Handler naming: `class-{feature}-{type}-handler.php`

Example:
```php
// Gets handler for current version, falls back to base if not found
$handler = Utility::get_handler_object( 'saml_request', true, 'saml' );
```

### Module Structure Pattern

Each module version follows the same structure:
```
module/{version}/
├── config/          # Version-specific configuration
├── exception/       # Version-specific exceptions
├── handler/        # Version-specific handlers
│   ├── admin/      # Admin form handlers
│   └── saml/       # SAML processing handlers
└── index.php
```

## Database Architecture

### Database Tables

All tables use the `mosaml_` prefix:

1. **`mosaml_environments`**: Multiple environment support
   - Stores different environments (dev, staging, production)
   - Fields: `id`, `environment_name`, `environment_url`, `selected`, `created_at`, `updated_at`

2. **`mosaml_idp_details`**: Identity Provider configuration
   - Stores IdP metadata and settings
   - Fields: `idp_id`, `idp_name`, `idp_entity_id`, `sso_url`, `x509_certificate`, etc.

3. **`mosaml_sp_metadata`**: Service Provider metadata
   - Stores SP entity ID, ACS URL, SLO URL, certificates
   - Fields: `sp_id`, `sp_entity_id`, `acs_url`, `slo_url`, `x509_certificate`, etc.

4. **`mosaml_subsites`**: Multisite support
   - Stores subsite-specific configurations
   - Fields: `subsite_id`, `environment_id`, `idp_id`, etc.

5. **`mosaml_attribute_mapping`**: Attribute mapping configuration
   - Maps SAML attributes to WordPress user fields
   - Fields: `mapping_id`, `idp_id`, `saml_attribute`, `wordpress_field`, etc.

6. **`mosaml_role_mapping`**: Role mapping configuration
   - Maps SAML attributes/values to WordPress roles
   - Fields: `role_mapping_id`, `idp_id`, `saml_attribute`, `attribute_value`, `wordpress_role`, etc.

7. **`mosaml_sso_settings`**: SSO settings
   - Stores SSO redirection and behavior settings
   - Fields: `setting_id`, `idp_id`, `sso_enabled`, `auto_redirect`, etc.

### Database Operations

- **Table Creation**: `DB_Queries::create_*_table()` methods
- **CRUD Operations**: `DB_Queries` class methods
- **Query Preparation**: Always use `$wpdb->prepare()` with placeholders
- **Database Utilities**: `DB_Utils` class for common operations

## Security Architecture

### Security Layers

1. **Input Sanitization**:
   - Use `Utility::sanitize_request_data()` for all request parameters
   - Always use `wp_unslash()` before sanitizing POST/GET data
   - Sanitize after processing, not before

2. **Output Escaping**:
   - Use `esc_html()`, `esc_attr()`, `esc_url()`, `esc_js()` for all output
   - Escape late, just before output

3. **Nonce Verification**:
   - Use `check_admin_referer()` for admin forms
   - Use `check_ajax_referer()` for AJAX requests
   - Always verify nonces before processing user input

4. **Capability Checks**:
   - Use `current_user_can( 'manage_options' )` for admin operations
   - Never rely on user roles - always use capabilities

5. **SAML Security**:
   - Disable external entity loading: `libxml_disable_entity_loader( true )`
   - Verify SAML response signatures
   - Validate assertion timestamps
   - Check audience restrictions
   - Prevent replay attacks

6. **File Protection**:
   - All directories must have `index.php` files
   - Certificate files protected by `.htaccess`
   - All PHP files must have `ABSPATH` check

### Security Principle: "Sanitize Early, Validate Early, Escape Late"

- **Sanitize Early**: Clean and filter input data before storing or using in code
- **Validate Early**: Once data is sanitized, validate it. If sanitization is not possible, always validate
- **Escape Late**: Escape output data as late as possible to prevent XSS attacks

### OWASP Top 10 Security Considerations

1. **Injection Attacks**: Always use prepared statements, disable external entities for XML
2. **Broken Authentication**: Verify nonces, check capabilities, validate SAML signatures
3. **Sensitive Data Exposure**: Protect certificates, encrypt sensitive data, never log secrets
4. **XML External Entities (XXE)**: Always disable external entity loading for SAML XML
5. **Broken Access Control**: Check capabilities for all operations
6. **Security Misconfiguration**: Include ABSPATH checks, protect files with .htaccess
7. **Cross-Site Scripting (XSS)**: Escape all output before display
8. **Insecure Deserialization**: Validate serialized data structure
9. **Using Components with Known Vulnerabilities**: Keep dependencies updated
10. **Insufficient Logging & Monitoring**: Log security events, never log sensitive data

> **See**: [`docs/instructions.md`](instructions.md#security-implementation) for detailed security implementation guidelines.

## Code Quality & Standards

### Coding Standards

1. **WordPress Coding Standards (WPCS)**:
   - Follow WordPress PHP Coding Standards
   - Use WordPress PHPCS ruleset
   - Run PHPCS before committing code

2. **Plugin Check Plugin (PCP)**:
   - **MANDATORY**: Must pass with zero issues before:
     - Submitting pull requests
     - Requesting code review
     - Publishing to WordPress.org
     - Releasing new versions

3. **Code Quality Tools**:
   - PHPCS (PHP CodeSniffer) with WordPress ruleset
   - WPCS (WordPress Coding Standards)
   - Plugin Check Plugin validation

### Naming Conventions

- **Namespace**: `MOSAML\SRC\{Category}\{Class_Name}`
- **Classes**: PascalCase with underscores: `Class_Name`
- **Files**: Lowercase with hyphens: `class-feature-name.php`
- **Functions**: Lowercase with underscores, prefixed: `mosaml_function_name()`
- **Constants**: UPPERCASE with underscores: `MOSAML_CONSTANT`
- **Database Tables**: Prefixed with `mosaml_`
- **WordPress Options**: Prefixed with `mosaml_`

### Documentation Requirements

- PHPDoc comments for all classes and methods
- Document parameters, return values, and exceptions
- Include `@package` tag: `miniorange-saml-20-single-sign-on`
- Translator comments for translatable strings

### Internationalization

- **Text Domain**: Always use `'miniorange-saml-20-single-sign-on'` (string literal)
- **Translation Functions**: Use `esc_html__()`, `esc_html_e()`, `printf()` with placeholders
- **NEVER** use variables for text domain or translatable strings

## Development Workflow

### Pre-Commit Checklist

1. **Code Quality**:
   - [ ] Run PHPCS with WordPress ruleset
   - [ ] Run Plugin Check Plugin (PCP) - must pass with zero issues
   - [ ] Fix all linter errors and warnings

2. **Security**:
   - [ ] Verify all input is sanitized
   - [ ] Verify all output is escaped
   - [ ] Verify nonces are checked
   - [ ] Verify capabilities are checked
   - [ ] Verify database queries use prepared statements

3. **Testing**:
   - [ ] Test SAML login flow
   - [ ] Test admin form submissions
   - [ ] Test error handling
   - [ ] Test with invalid input
   - [ ] Test security measures

4. **Documentation**:
   - [ ] PHPDoc comments added/updated
   - [ ] Code follows naming conventions
   - [ ] Translation strings use correct text domain

### File Organization Rules

1. **Every PHP file must**:
   - Start with `ABSPATH` check
   - Include proper file header with `@package` tag
   - Use correct namespace

2. **Every directory must**:
   - Have an `index.php` file with "Silence is golden" comment

3. **Protected files**:
   - Certificate files (`.key`, `.crt`, `.pem`) must be protected by `.htaccess`

### Documentation Files Reference

When developing, always refer to:

1. **`.cursorrules`**: Generic WordPress plugin development guidelines
2. **`docs/instructions.md`**: Plugin-specific instructions and code patterns
3. **`docs/ARCHITECTURE.md`**: This file - plugin architecture overview

### Priority Order (if conflicts arise):

1. `docs/instructions.md` - Plugin-specific requirements and security implementation
2. `docs/ARCHITECTURE.md` - File organization and component structure
3. `.cursorrules` - General WordPress best practices

## Key Patterns

### Handler Pattern

```php
// Get handler object (version-specific or base fallback)
$handler = Utility::get_handler_object( 'feature_name', true, 'handler_type' );
$handler->process_request( $data );
```

### Controller Pattern

```php
// Controller receives request, creates DTO, delegates to handler
$dto = new SAML_Request_DTO( $request_data );
$handler = Utility::get_handler_object( 'saml_request', true, 'saml' );
$handler->handle_request( $dto );
```

### DTO Pattern

```php
// Create DTO with data
$dto = new SAML_Response_DTO();
$dto->set_saml_response( $response_xml );
$dto->set_relay_state( $relay_state );

// Pass to handler
$handler->process_response( $dto );
```

### Database Pattern

```php
// Use DB_Utils for common operations
$db_utils = DB_Utils::get_instance();
$result = $db_utils->insert_or_update_query(
    Constants::DATABASE_TABLE_NAMES['idp_details'],
    $data,
    $where
);

// Or use DB_Queries for specific operations
$db_queries = DB_Queries::instance();
$result = $db_queries->get_idp_details( $idp_id );
```

## Resources

### Plugin Files
- Constants: `src/constant/class-constants.php`
- Plugin Options: `src/constant/class-plugin-options.php`
- Error Codes: `src/constant/class-error-codes-enums.php`
- Utility Functions: `src/utils/class-utility.php`
- Database Utils: `src/utils/class-db-utils.php`

### Documentation
- **Architecture**: `docs/ARCHITECTURE.md` (this file)
- **Instructions**: `docs/instructions.md`
- **Development Rules**: `.cursorrules`

### External Resources
- WordPress Plugin Handbook: https://developer.wordpress.org/plugins/
- WordPress Coding Standards: https://developer.wordpress.org/coding-standards/
- Plugin Check Plugin: https://wordpress.org/plugins/plugin-check/
- OWASP Top 10: https://owasp.org/www-project-top-ten/
