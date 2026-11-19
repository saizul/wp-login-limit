<?php
/**
 * Removes the plugin's tables, options and user meta when it is deleted from the Plugins screen.
 *
 * @package Saizul\LoginLimit
 */

defined( 'WP_UNINSTALL_PLUGIN' ) || exit;

/**
 * Drop the tables and delete the options of the current site.
 */
function wp_login_limit_uninstall_site() {
	global $wpdb;
	foreach ( array( 'login_limit_attempts', 'login_limit_log' ) as $wp_login_limit_table ) {
		$wpdb->query( $wpdb->prepare( 'DROP TABLE IF EXISTS %i', $wpdb->prefix . $wp_login_limit_table ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.NotPrepared
	}
	delete_option( 'wp_login_limit_settings' );
	delete_option( 'wp_login_limit_db_version' );
	delete_option( 'wp_login_limit_notify_state' );
	wp_clear_scheduled_hook( 'wp_login_limit_purge' );
}

if ( is_multisite() ) {
	$wp_login_limit_site_ids = get_sites(
		array(
			'fields' => 'ids',
			'number' => 0,
		)
	);
	foreach ( $wp_login_limit_site_ids as $wp_login_limit_site_id ) {
		switch_to_blog( (int) $wp_login_limit_site_id );
		wp_login_limit_uninstall_site();
		restore_current_blog();
	}
} else {
	wp_login_limit_uninstall_site();
}

// Known networks are stored per user (users are shared by every site of a network).
delete_metadata( 'user', 0, 'wp_login_limit_known_networks', '', true );
