<?php
/**
 * Configure IDP Warning Template.
 *
 * @package miniorange-saml-20-single-sign-on
 */
// phpcs:ignoreFile WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedVariableFound -- Template scope variables.

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\SRC\Constant\Constants;
?>
<?php if ( get_option( Constants::DISMISSED_DATABASE_UPDATE_REQUIRED_NOTICE_OPTION_NAME )) : ?>
	<div class="mosaml-tab-content-section mosaml-margin-top-bottom-0-2-rem">
		<div>
			<h1>Database Update Required</h1>
			<b>Please update your database to the latest version to continue using the miniOrange SAML SSO plugin.</b>
			<p style="color: red; font-style: italic;">
				Note: Your <b>SSO functionality will continue to work</b> without any issues during this process.
			</p>
		</div>
	</div>
<?php endif; ?>
<div class="mosaml-tab-content-section mosaml-margin-top-bottom-0-2-rem">
	<?php if ( 'completed' !== $db_update_status ) : ?>
		<div>
			<?php if ( ! empty( $tables_to_show_sql_queries ) ) : ?>
				<h2>Required Database Tables</h2>
				<div class="mosaml-div-flex-row" style="justify-content: space-between;">
					<span>Run the below queries manually in your WordPress database to create the required database tables.</span>
					<div class="mosaml-div-flex">
						<button class="button button-large" 
								onclick="copyToClipboard(this, '#mosaml_all_db_update_queries', '#mosaml_all_db_update_queries_copy');">
							<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="bi bi-copy" viewBox="0 0 16 16">
								<path fill-rule="evenodd" d="M4 2a2 2 0 0 1 2-2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2zm2-1a1 1 0 0 0-1 1v8a1 1 0 0 0 1 1h8a1 1 0 0 0 1-1V2a1 1 0 0 0-1-1zM2 5a1 1 0 0 0-1 1v8a1 1 0 0 0 1 1h8a1 1 0 0 0 1-1v-1h1v1a2 2 0 0 1-2 2H2a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2h1v1z"/>
							</svg>
							Copy SQL
						</button>
						<button class="button button-large button-primary" onclick="downloadDatabaseUpdateQueries();">Download SQL</button>
					</div>
				</div>
				<br>
			<?php else : ?>
				<h2>Update Database</h2>
			<?php endif; ?>

			<div class="mosaml-div-flex-row" style="justify-content: space-between;">
				<?php if ( ! empty( $tables_to_show_sql_queries ) ) : ?>
					<span class="mosaml-red-text">Note: Once you have run the queries, please click on the <b>Setup Database</b> button to complete the database setup.</span>
				<?php else : ?>
					<span class="mosaml-red-text">Please click on the <b>Setup Database</b> button to complete the database setup.</span>
				<?php endif; ?>
				<button class="button button-large button-primary" onclick="setupDatabase();">Setup Database</button>
			</div>
			<form id="mosaml_setup_database_form" method="post" action="">
				<?php wp_nonce_field( 'mosaml_setup_database' ); ?>
				<input type="hidden" name="option" value="mosaml_setup_database">
			</form>
			<?php if ( ! empty( $tables_to_show_sql_queries ) ) : ?>
				<hr>
				<div style="margin: 0 3rem 0 3rem;">
					<?php $all_sql = ''; ?>
					<?php foreach ( $tables_to_show_sql_queries as $table_name ) : ?>
						<?php $all_sql .= $table_queries_object->{$table_name}['create_table'] . "\n\n"; ?>
						<p><b><?php echo esc_html( $table_name ); ?></b></p>
						<pre><code><i><?php echo esc_html( $table_queries_object->{$table_name}['create_table'] ); ?></i></code></pre>
						<?php if ( ! empty( $table_queries_object->{$table_name}['add_constraint'] ) ) : ?>
							<?php foreach ( $table_queries_object->{$table_name}['add_constraint'] as $constraint_name => $sql ) : ?>
								<pre><code><i><?php echo esc_html( $sql ); ?></i></code></pre>
								<?php $all_sql .= $sql . "\n\n"; ?>
							<?php endforeach; ?>
						<?php endif; ?>
						<hr>
					<?php endforeach; ?>
					<textarea id="mosaml_all_db_update_queries" style="display:none;"><?php echo esc_textarea( $all_sql ); ?></textarea>
				</div>
			<?php endif; ?>
		</div>
	<?php else : ?>
		<div class="mosaml-div-flex-row" style="justify-content: space-between;">
			Are you sure you want to update the database now?
			<button onclick="updateDatabase();" class="button button-large button-primary">Update Database</button>
		</div>
		<form id="mosaml_update_database_form" method="post" action="">
			<?php wp_nonce_field( 'mosaml_update_database' ); ?>
			<input type="hidden" name="option" value="mosaml_update_database">
		</form>
	<?php endif; ?>
</div>
