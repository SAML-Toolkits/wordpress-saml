# Plugin-Specific Instructions: miniOrange SAML 2.0 SSO

This document contains plugin-specific instructions, code patterns, security implementation, development rules, and usage examples for the miniOrange SAML 2.0 Single Sign-On WordPress plugin.

> **Note**: For complete architecture details, directory structure, and component organization, see [`docs/ARCHITECTURE.md`](ARCHITECTURE.md).

## Plugin Overview

**Plugin Name**: miniOrange SAML SSO  
**Plugin Slug**: `miniorange-saml-20-single-sign-on`  
**Namespace**: `MOSAML`  
**Text Domain**: `miniorange-saml-20-single-sign-on`  
**Main File**: `login.php`  
**Version**: 26.0.0

## Required Documentation References

**MANDATORY**: When developing, refer to these documentation files:

1. **`docs/ARCHITECTURE.md`** - Complete plugin architecture and directory structure
2. **`docs/instructions.md`** - This file - plugin-specific instructions and patterns
3. **`.cursorrules`** - Generic WordPress plugin development guidelines

**Enforcement Rules**:
- ✅ ALWAYS check all documentation files before writing code
- ✅ Follow architecture from `docs/ARCHITECTURE.md` for file organization
- ✅ Follow guidelines from `docs/instructions.md` for plugin-specific patterns
- ✅ Follow guidelines from `.cursorrules` for general WordPress practices
- ❌ NEVER skip referencing any of these files
- ❌ NEVER generate code that violates guidelines in any of these files

**Priority Order** (if conflicts arise):
1. `docs/instructions.md` - Plugin-specific requirements and security implementation (this file)
2. `docs/ARCHITECTURE.md` - File organization and component structure
3. `.cursorrules` - General WordPress best practices

## Hidden Files

The plugin includes hidden files such as `.cursorrules` (development guidelines) and `.htaccess` under `resource/` and `static/resource/` for access control. These are intentionally retained even though automated checks like PCP may flag hidden files.

## Naming Conventions

### Prefixes
- **Plugin Prefix**: `mosaml_` (used for database tables, options, hooks)
- **Namespace**: `MOSAML`
- **Text Domain**: `miniorange-saml-20-single-sign-on` (always use string literal)
- **Constants Prefix**: `MOSAML_` (e.g., `MOSAML_PLUGIN_DIR`, `MOSAML_VERSION`)

### Class Naming
- Use PascalCase with underscores: `Class_Name`
- File pattern: `class-{feature}-{type}.php`
- Examples:
  - `class-init-controller.php` → `Init_Controller`
  - `class-saml-request-handler.php` → `SAML_Request_Handler`
  - `class-user-login-handler.php` → `User_Login_Handler`

### Function Naming
- Use lowercase with underscores
- Prefix with `mosaml_` for global functions only
- Examples: `mosaml_autoload_files()`, `mosaml_sanitize_request()`

### Database Tables
All tables use the `mosaml_` prefix:
- `mosaml_environments`
- `mosaml_idp_details`
- `mosaml_sp_metadata`
- `mosaml_subsites`
- `mosaml_attribute_mapping`
- `mosaml_sso_settings`
- `mosaml_role_mapping`

> **See**: [`docs/ARCHITECTURE.md`](ARCHITECTURE.md#database-architecture) for complete database schema.

## Code Organization Patterns

### Autoloading
- Uses custom autoloader: `mosaml_autoload_files()`
- Namespace-based class loading
- Converts namespace to file path automatically
- Example: `MOSAML\SRC\Controller\Init_Controller` → `src/controller/class-init-controller.php`

### Handler Pattern
Handlers are organized by type and resolved via `Utility::get_handler_object()`:
- **Admin Handlers**: `module/*/handler/admin/` - Handle admin form submissions
- **SAML Handlers**: `module/*/handler/saml/` - Handle SAML requests/responses
- **UI Handlers**: `src/handler/ui/` - Handle UI rendering logic

> **See**: [`docs/ARCHITECTURE.md`](ARCHITECTURE.md#core-components) for complete handler organization.

### DTO Pattern
Data Transfer Objects in `src/dto/`:
- `SAML_Request_DTO` - SAML request data
- `SAML_Response_DTO` - SAML response data
- `User_Attributes_DTO` - User attribute data
- `Assertions_DTO` - SAML assertion data

### Controller Pattern
Controllers in `src/controller/`:
- `Init_Controller` - Handles public-facing SAML requests
- `Admin_Init_Controller` - Handles admin form submissions
- `Logout_Controller` - Handles SAML logout

## Key Constants

### Plugin Constants
```php
MOSAML_PLUGIN_DIR    // Plugin directory path
MOSAML_PLUGIN_FILE   // Main plugin file path
MOSAML_VERSION       // Current plugin version (1-4)
```

### Database Tables
Defined in `src/constant/class-constants.php`:
```php
Constants::DATABASE_TABLE_NAMES
```

### Plugin Options
Defined in `src/constant/class-plugin-options.php`:
```php
Plugin_Options::SAML_REQUEST_OPTION
Plugin_Options::SAML_RESPONSE_OPTION
```

## Utility Functions

### Request Sanitization
Always use `Utility::sanitize_request_data()`:
```php
$option = Utility::sanitize_request_data( 'option' );
$idp_id = absint( Utility::sanitize_request_data( 'idp_id' ) );
```

> **Security Note**: See [Security Implementation](#security-implementation) section for security principles.

### Handler Object Creation
Use `Utility::get_handler_object()`:
```php
$handler = Utility::get_handler_object( 'saml_request', true, 'saml' );
$admin_handler = Utility::get_handler_object( 'attribute_mapping_data', true, 'admin' );
```

The method automatically resolves version-specific handlers with base fallback.

### User Lookup
Use `Utility::get_user_by_username_or_email()`:
```php
$user = Utility::get_user_by_username_or_email( $username, $email );
```

## Database Operations

### Using DB_Utils
The plugin uses `DB_Utils` class for database operations:
```php
$db_utils = DB_Utils::get_instance();
$result = $db_utils->insert_or_update_query( $table, $data, $where );
```

### Query Preparation
Always use prepared statements:
```php
global $wpdb;
$table = Constants::DATABASE_TABLE_NAMES['idp_details'];
$result = $wpdb->get_results(
    $wpdb->prepare(
        "SELECT * FROM {$table} WHERE idp_id = %d AND status = %s",
        absint( $idp_id ),
        sanitize_text_field( $status )
    ),
    ARRAY_A
);
```

> **Security Note**: See [Security Implementation](#security-implementation) section for SQL injection prevention.

## SAML Processing

### Request Handling Flow
1. Controller receives request (`Init_Controller::init_actions()`)
2. Creates `SAML_Request_DTO`
3. Gets handler via `Utility::get_handler_object()`
4. Handler processes request and redirects to IdP

### Response Handling Flow
1. Controller receives SAML response
2. Validates and parses XML (with external entities disabled)
3. Verifies signature
4. Validates assertion (timestamp, audience, issuer)
5. Creates/updates user via `User_Login_Handler`
6. Logs user in

### Key Classes
- `SAML_Request_Handler` - Handles SAML authentication requests
- `SAML_Response_Handler` - Handles SAML responses
- `User_Login_Handler` - Handles user creation/login
- `Attribute_Mapping_Handler` - Maps SAML attributes to WordPress user data

> **Security Note**: See [Security Implementation](#security-implementation) section for SAML security requirements.

## Error Handling

### Exception Classes
Custom exceptions in `src/exception/`:
- `Invalid_Assertion_Exception`
- `Invalid_XML_Exception`
- `Signature_Not_Found_Exception`
- `Metadata_Validation_Exception`
- And 20+ more specialized exceptions

### Error Display
Use `Error_Success_Message::display_error_code_message()`:
```php
Error_Success_Message::display_error_code_message(
    Error_Codes_Enums::$error_codes['WPSAMLERR037']
);
```

## Internationalization

### Text Domain
Always use: `'miniorange-saml-20-single-sign-on'` (string literal, never a variable)

### Translation Functions
```php
esc_html__( 'Text to translate', 'miniorange-saml-20-single-sign-on' );
esc_html_e( 'Text to translate', 'miniorange-saml-20-single-sign-on' );
printf(
    /* translators: %s: User name */
    esc_html__( 'Hello %s', 'miniorange-saml-20-single-sign-on' ),
    esc_html( $username )
);
```

### Important
- **NEVER use variables** for text domain or translatable strings
- Always use string literals for translation functions
- Include translator comments for context

## Version-Specific Code

### Module Structure
- Base module: Common functionality for all versions
- Standard/Premium/Enterprise: Version-specific features
- Use `MOSAML_VERSION` constant to check version
- Use `Feature_Control::check_is_license_verified()` for license checks

### Handler Resolution
Handlers are resolved based on version:
1. Check if version-specific handler exists in `module/{version}/handler/{type}/`
2. Fall back to base handler in `module/base/handler/{type}/`
3. Use `Utility::get_handler_object()` for resolution

> **See**: [`docs/ARCHITECTURE.md`](ARCHITECTURE.md#module-system) for complete module system documentation.

## Security Implementation

### Security Principle: "Sanitize Early, Validate Early, Escape Late"

#### Sanitize Early
- **Clean and filter input data before storing or using in code**
- Sanitize all values from super global variables: `$_POST`, `$_GET`, `$_REQUEST`, `$_COOKIE`, `$_SESSION`, etc.
- Sanitization should be done AFTER all processing is done to the input
- ❌ **Incorrect**: `base64_decode( htmlspecialchars( $_COOKIE['sessionid'] ) )`
- ✅ **Correct**: `sanitize_text_field( base64_decode( $_COOKIE['sessionid'] ) )`
- Use WordPress sanitization functions: https://developer.wordpress.org/apis/security/sanitizing/

#### Validate Early
- **Once data is sanitized, validate it. If sanitization is not possible, always validate**
- Check required fields are not blank
- Validate format (email, phone, URL, etc.)
- Use whitelist/blocklist for known values
- Use format detection (preg_match) or format correction (preg_replace)
- WordPress validation functions: https://developer.wordpress.org/apis/security/data-validation/

#### Escape Late
- **Escape output data as late as possible to prevent XSS attacks**
- Escape everything: databases, users, third parties (Twitter, etc.)
- When escaping early is necessary, use variable naming: `$variable_escaped`, `$variable_safe`, or `$variable_clean`
- ❌ **Bad**: `echo '<a href="' . $url . '">' . $text . '</a>';`
- ✅ **Better**: `echo '<a href="' . esc_url( $url ) . '">' . esc_html( $text ) . '</a>';`
- WordPress escaping functions: https://developer.wordpress.org/apis/security/escaping/

### Nonce Verification
- **MANDATORY**: Verify nonces for ALL form submissions and AJAX requests
- Use `check_admin_referer()` for admin forms (handles both nonce and referer check)
- Use `check_ajax_referer()` for AJAX requests
- Use `wp_verify_nonce()` for custom nonce verification
- Example:
  ```php
  // Admin form
  check_admin_referer( 'action_name', '_wpnonce' );
  
  // AJAX request
  check_ajax_referer( 'action_name', 'nonce' );
  ```

### Capability Checks
- **ALWAYS check user capabilities before performing sensitive operations**
- Use `current_user_can( 'manage_options' )` for admin-only operations
- Use `current_user_can( 'edit_posts' )` for content editing
- Never rely on user roles - use capabilities
- Example:
  ```php
  if ( ! current_user_can( 'manage_options' ) ) {
      wp_die( esc_html__( 'You do not have permission to access this page.', 'miniorange-saml-20-single-sign-on' ) );
  }
  ```

### Input Sanitization

**Plugin-Specific Method**: `Utility::sanitize_request_data()`
- **MUST** use `Utility::sanitize_request_data()` for all request parameters
- This method automatically handles `wp_unslash()` and `sanitize_text_field()`
- **MUST** sanitize after processing, not before
- **MUST** use appropriate sanitization functions:
  - `Utility::sanitize_request_data()` - For request parameters (plugin-specific)
  - `sanitize_text_field()` - For text inputs
  - `sanitize_email()` - For email addresses
  - `absint()` - For positive integers
  - `wp_kses()` - For HTML content
- Example:
  ```php
  // Plugin-specific method (recommended)
  $option = Utility::sanitize_request_data( 'option' );
  $idp_id = absint( Utility::sanitize_request_data( 'idp_id' ) );
  
  // Generic WordPress method (also valid)
  $option = sanitize_text_field( wp_unslash( $_REQUEST['option'] ?? '' ) );
  ```

### Output Escaping
- **MUST** escape all output before display
- **MUST** use appropriate escaping functions:
  - `esc_html()` - HTML content
  - `esc_attr()` - HTML attributes
  - `esc_url()` - URLs
  - `esc_js()` - JavaScript
- Example:
  ```php
  echo '<div>' . esc_html( $user_name ) . '</div>';
  echo '<a href="' . esc_url( $url ) . '">Link</a>';
  ```

### SAML Security

**Plugin-Specific Exception Classes**: Use plugin-specific exceptions for SAML errors
- `Invalid_Assertion_Exception` - For invalid SAML assertions
- `Invalid_XML_Exception` - For XML parsing errors
- `Signature_Not_Found_Exception` - For missing signatures
- `Metadata_Validation_Exception` - For metadata validation errors
- See `src/exception/` for complete list

**Implementation Requirements**:
- **MUST** disable external entity loading: `libxml_disable_entity_loader( true )`
- **MUST** verify SAML response signatures
- **MUST** validate assertion timestamps
- **MUST** check audience restrictions
- **MUST** validate issuer
- **MUST** prevent replay attacks
- **MUST** use `Exception_Handler::throw_exception()` for user-facing errors
- Example:
  ```php
  libxml_disable_entity_loader( true );
  $dom = new DOMDocument();
  $dom->loadXML( $saml_response );
  
  // Verify signature
  if ( ! $this->verify_signature( $saml_response, $idp_certificate ) ) {
      throw new Invalid_Assertion_Exception( 'Invalid signature' );
  }
  
  // Handle exceptions
  try {
      // SAML processing
  } catch ( Invalid_Assertion_Exception $e ) {
      Exception_Handler::throw_exception( $e );
  }
  ```

### Database Security

#### Query Preparation
- **MUST** use `$wpdb->prepare()` for all queries with user input
- **MUST** use placeholders: `%d` (integer), `%s` (string), `%f` (float)
- **MUST** use `esc_sql()` for table/column names (prefer whitelisting)
- **NEVER** concatenate user input into SQL queries
- Example:
  ```php
  $wpdb->prepare(
      "SELECT * FROM {$table} WHERE idp_id = %d AND status = %s",
      absint( $idp_id ),
      sanitize_text_field( $status )
  );
  ```

#### Database Utilities

**Plugin-Specific Class**: `DB_Utils`
- **SHOULD** use `DB_Utils` class for database operations
- **SHOULD** use `insert_or_update_query()` when appropriate
- **MUST** sanitize all data before database operations
- This class provides a wrapper around `$wpdb` with additional safety checks
- Example:
  ```php
  $db_utils = DB_Utils::get_instance();
  $db_utils->insert_or_update_query(
      Constants::DATABASE_TABLE_NAMES['idp_details'],
      array(
          'name' => sanitize_text_field( $name ),
          'idp_id' => absint( $idp_id ),
      ),
      array( 'idp_id' => absint( $idp_id ) )
  );
  ```

### File Protection
- **MANDATORY**: Include `index.php` in every directory to prevent directory listing
- Add `ABSPATH` check at the top of every PHP file:
  ```php
  if ( ! defined( 'ABSPATH' ) ) {
      exit; // Exit if accessed directly
  }
  ```
- Protect certificate files with `.htaccess`:
  ```apache
  Options -Indexes
  <Files ~ "\.(crt|cer|key|pem)$">
      Order allow,deny
      Deny from all
  </Files>
  ```

### OWASP Top 10 Security Considerations

1. **Injection Attacks (SQL, Command, LDAP, etc.)**:
   - Always use `$wpdb->prepare()` with placeholders
   - Disable external entity loading for XML: `libxml_disable_entity_loader( true )`
   - Never use `exec()`, `system()`, `shell_exec()` with user input

2. **Broken Authentication**:
   - Verify nonces for all form submissions
   - Check capabilities before sensitive operations
   - Verify SAML response signatures

3. **Sensitive Data Exposure**:
   - Never store private keys in plain text
   - Protect certificate files with `.htaccess`
   - Never log sensitive information

4. **XML External Entities (XXE)**:
   - **CRITICAL**: Disable external entity loading when processing SAML XML
   - Use `libxml_disable_entity_loader( true )` before parsing any XML

5. **Broken Access Control**:
   - Verify user permissions for every action
   - Check capabilities, not just user roles

6. **Security Misconfiguration**:
   - Include `ABSPATH` check in every PHP file
   - Include `index.php` in every directory

7. **Cross-Site Scripting (XSS)**:
   - Always escape output before displaying to users
   - Use appropriate escaping functions

8. **Insecure Deserialization**:
   - Never deserialize data from untrusted sources
   - Validate serialized data structure

9. **Using Components with Known Vulnerabilities**:
   - Keep all dependencies up to date
   - Monitor security advisories

10. **Insufficient Logging & Monitoring**:
    - Log all authentication attempts
    - Never log sensitive information

## Common Code Patterns

### Form Submission Handler
```php
public function handle_form_submission() {
    // 1. Verify nonce
    check_admin_referer( 'action_name', '_wpnonce' );
    
    // 2. Check capability
    if ( ! current_user_can( 'manage_options' ) ) {
        wp_die( esc_html__( 'Unauthorized', 'miniorange-saml-20-single-sign-on' ) );
    }
    
    // 3. Sanitize input
    $value = Utility::sanitize_request_data( 'field_name' );
    
    // 4. Validate input
    if ( empty( $value ) ) {
        Error_Success_Message::display_error_code_message(
            Error_Codes_Enums::$error_codes['ERROR_CODE']
        );
        return;
    }
    
    // 5. Process data
    // ...
    
    // 6. Redirect or display message
}
```

### SAML Request Processing
```php
// 1. Disable external entities (CRITICAL for security)
libxml_disable_entity_loader( true );

// 2. Parse XML
$dom = new DOMDocument();
$dom->loadXML( $saml_response );

// 3. Verify signature
if ( ! $this->verify_signature( $dom, $idp_certificate ) ) {
    throw new Invalid_Assertion_Exception( 'Invalid signature' );
}

// 4. Validate assertion
$this->validate_assertion( $dom );

// 5. Process user login
$user_login_handler = Utility::get_handler_object( 'user_login', true, 'core' );
$user_login_handler->handle_user_login( $saml_response_dto );
```

### Database Query Pattern
```php
$db_utils = DB_Utils::get_instance();
$result = $db_utils->insert_or_update_query(
    Constants::DATABASE_TABLE_NAMES['idp_details'],
    array(
        'name' => sanitize_text_field( $name ),
        'idp_id' => absint( $idp_id ),
    ),
    array( 'idp_id' => absint( $idp_id ) )
);
```

## File Structure Requirements

### ABSPATH Check
Every PHP file must start with:
```php
if ( ! defined( 'ABSPATH' ) ) {
    exit;
}
```

### Index Files
Every directory must have an `index.php` file:
```php
<?php
// Silence is golden.
```

### Protected Files
Certificate files (`.key`, `.crt`, `.pem`) must be protected with `.htaccess`:
```apache
Options -Indexes
<Files ~ "\.(crt|cer|key|pem)$">
    Order allow,deny
    Deny from all
</Files>
```

## Development Rules

### File Structure Rules

#### File Naming
- **MUST** use lowercase with hyphens: `class-feature-name.php`
- **MUST** prefix class files with `class-`
- **MUST** match class name pattern: `Class_Feature_Name`
- Examples:
  - `class-init-controller.php` → `Init_Controller`
  - `class-saml-request-handler.php` → `SAML_Request_Handler`

#### Required File Header
Every PHP file **MUST** start with:
```php
<?php
/**
 * File description.
 *
 * @package miniorange-saml-20-single-sign-on
 */

namespace MOSAML\SRC\Category;

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}
```

### Code Organization Rules

#### Handler Pattern
- **MUST** organize handlers by type as defined in `docs/ARCHITECTURE.md`
- **MUST** use `Utility::get_handler_object()` to get handlers
- **MUST** follow naming convention: `{Feature}_Handler`
- Handlers are resolved with version-specific → base fallback

#### Controller Pattern
- **MUST** use controllers for request handling:
  - `Init_Controller` - Public SAML requests
  - `Admin_Init_Controller` - Admin form submissions
  - `Logout_Controller` - SAML logout
- **MUST** keep controllers thin - delegate to handlers

#### DTO Pattern
- **MUST** use DTOs for data transfer:
  - `SAML_Request_DTO`
  - `SAML_Response_DTO`
  - `User_Attributes_DTO`
  - `Assertions_DTO`
- **MUST** use getters/setters for DTO properties

### Error Handling Rules

#### Exception Handling
- **MUST** use custom exception classes from `src/exception/`
- **MUST** catch specific exceptions, not generic `Exception`
- **MUST** use `Exception_Handler::throw_exception()` for user-facing errors
- Example:
  ```php
  try {
      // SAML processing
  } catch ( Invalid_Assertion_Exception $e ) {
      Exception_Handler::throw_exception( $e );
  } catch ( Invalid_XML_Exception $e ) {
      Exception_Handler::throw_exception( $e );
  }
  ```

#### Error Messages
- **MUST** use `Error_Success_Message::display_error_code_message()` for user errors
- **MUST** use error codes from `Error_Codes_Enums`
- **MUST** never expose sensitive information in error messages
- Example:
  ```php
  Error_Success_Message::display_error_code_message(
      Error_Codes_Enums::$error_codes['WPSAMLERR037']
  );
  ```

### Version-Specific Rules

#### Version Detection
- **MUST** use `MOSAML_VERSION` constant to check version
- **MUST** use `Feature_Control::check_is_license_verified()` for license checks
- **MUST** check version before version-specific features

#### Module Structure
- **MUST** put common code in `module/base/`
- **MUST** put version-specific code in `module/{version}/`
- **MUST** extend base handlers in version-specific modules

## Testing Requirements

### Pre-Commit Checklist
- [ ] Run Plugin Check Plugin (PCP) - must pass with zero issues
- [ ] Run PHPCS with WordPress ruleset
- [ ] Test SAML login flow
- [ ] Test admin form submissions
- [ ] Test error handling
- [ ] Verify nonce verification works
- [ ] Check capability checks
- [ ] Test with invalid input
- [ ] Test security measures

### Security Testing
- [ ] Test with invalid SAML responses
- [ ] Test with missing nonces
- [ ] Test with insufficient capabilities
- [ ] Test SQL injection attempts
- [ ] Test XSS attempts
- [ ] Test XXE vulnerabilities
- [ ] Test redirect validation

## Prohibited Practices

### ❌ NEVER Do These

1. **Never skip nonce verification** - even for "safe" operations
2. **Never skip capability checks** - even for admins
3. **Never concatenate user input into SQL** - always use prepared statements
4. **Never output unescaped data** - always escape before output
5. **Never process XML without disabling external entities** - security risk
6. **Never trust SAML responses without verification** - always verify signature
7. **Never use variables for text domain** - breaks translation
8. **Never hardcode paths** - use `__FILE__` and WordPress functions
9. **Never expose sensitive data** - in errors, logs, or output
10. **Never skip ABSPATH check** - security requirement

## Code Quality Rules

### Documentation
- **MUST** add PHPDoc comments for all classes and methods
- **MUST** document parameters and return values
- **MUST** include `@package` tag: `miniorange-saml-20-single-sign-on`
- Example:
  ```php
  /**
   * Handles SAML authentication requests.
   *
   * @package miniorange-saml-20-single-sign-on
   */
  class SAML_Request_Handler {
      /**
       * Processes SAML request and redirects to IdP.
       *
       * @param SAML_Request_DTO $saml_request_dto The SAML request DTO.
       * @return void
       */
      public function handle_saml_request( SAML_Request_DTO $saml_request_dto ) {
          // ...
      }
  }
  ```

### Code Comments
- **SHOULD** explain "why", not "what"
- **MUST** remove unused code (don't just comment it out)
- **MUST NOT** comment CSS or HTML (visible in DOM)

### Performance
- **SHOULD** minimize database queries
- **SHOULD** use caching for expensive operations
- **SHOULD** avoid queries in loops

## Enforcement

### Code Review Checklist
- [ ] Follows namespace and prefix rules
- [ ] Follows directory structure from `docs/ARCHITECTURE.md`
- [ ] Includes ABSPATH check
- [ ] Verifies nonces
- [ ] Checks capabilities
- [ ] Sanitizes input
- [ ] Escapes output
- [ ] Uses prepared statements
- [ ] Handles errors properly
- [ ] Uses correct text domain
- [ ] Includes PHPDoc comments
- [ ] Passes Plugin Check Plugin (PCP)
- [ ] Passes PHPCS with WordPress ruleset

### Violation Consequences
- Code with security violations **MUST** be fixed before merge
- Code with naming violations **MUST** be fixed before merge
- Code failing PCP **MUST** be fixed before merge
- Code not following architecture **MUST** be fixed before merge
- All violations **MUST** be addressed in code review

## Resources

### Plugin Files
- Plugin Constants: `src/constant/class-constants.php`
- Plugin Options: `src/constant/class-plugin-options.php`
- Error Codes: `src/constant/class-error-codes-enums.php`
- Utility Functions: `src/utils/class-utility.php`
- Database Utils: `src/utils/class-db-utils.php`

### Documentation
- **Architecture**: [`docs/ARCHITECTURE.md`](ARCHITECTURE.md) - Complete plugin architecture
- **Instructions**: [`docs/instructions.md`](instructions.md) - This file
- **Development Rules**: `.cursorrules` - Generic WordPress guidelines

## Important Notes

1. **Always check license** before processing SAML requests (except metadata)
2. **Always verify nonces** for all form submissions
3. **Always check capabilities** for admin operations
4. **Always sanitize input** before use
5. **Always escape output** before display
6. **Always disable external entities** when parsing XML
7. **Always verify SAML signatures** before processing
8. **Always validate SAML assertions** (timestamp, audience, issuer)
9. **Never trust user input** - validate everything
10. **Never expose sensitive data** in error messages
