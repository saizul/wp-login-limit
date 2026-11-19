<?php
/**
 * Database tables.
 *
 * @package Saizul\LoginLimit
 */

namespace Saizul\LoginLimit;

defined( 'ABSPATH' ) || exit;

/**
 * Creates and upgrades the two custom tables with dbDelta().
 *
 * Counters live in a table, not in transients, because an object cache may
 * evict transients at any time, which would reset the counters.
 */
final class Schema {

	const VERSION        = '1';
	const VERSION_OPTION = 'wp_login_limit_db_version';

	/**
	 * Attempts table name.
	 */
	public static function attempts_table(): string {
		global $wpdb;

		return $wpdb->prefix . 'login_limit_attempts';
	}

	/**
	 * Log table name.
	 */
	public static function log_table(): string {
		global $wpdb;

		return $wpdb->prefix . 'login_limit_log';
	}

	/**
	 * CREATE TABLE statements in dbDelta() format.
	 *
	 * @param string $charset_collate Charset and collation clause.
	 * @return string[]
	 */
	public static function statements( string $charset_collate ): array {
		$attempts = self::attempts_table();
		$log      = self::log_table();

		return array(
			"CREATE TABLE {$attempts} (
  lock_key varchar(191) NOT NULL,
  kind varchar(10) NOT NULL DEFAULT 'ip',
  value varchar(180) NOT NULL DEFAULT '',
  failures int(10) unsigned NOT NULL DEFAULT 0,
  window_start bigint(20) unsigned NOT NULL DEFAULT 0,
  lockouts int(10) unsigned NOT NULL DEFAULT 0,
  locked_until bigint(20) unsigned NOT NULL DEFAULT 0,
  last_lockout bigint(20) unsigned NOT NULL DEFAULT 0,
  updated_at bigint(20) unsigned NOT NULL DEFAULT 0,
  PRIMARY KEY  (lock_key),
  KEY locked_until (locked_until),
  KEY updated_at (updated_at)
) {$charset_collate};",
			"CREATE TABLE {$log} (
  id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  created_at bigint(20) unsigned NOT NULL DEFAULT 0,
  event varchar(20) NOT NULL DEFAULT '',
  ip varchar(64) NOT NULL DEFAULT '',
  username varchar(100) NOT NULL DEFAULT '',
  gateway varchar(20) NOT NULL DEFAULT '',
  duration int(10) unsigned NOT NULL DEFAULT 0,
  level int(10) unsigned NOT NULL DEFAULT 0,
  PRIMARY KEY  (id),
  KEY created_at (created_at)
) {$charset_collate};",
		);
	}

	/**
	 * Create or upgrade the tables when the stored version is older.
	 */
	public static function maybe_install(): void {
		if ( self::VERSION === get_option( self::VERSION_OPTION ) ) {
			return;
		}
		self::install();
	}

	/**
	 * Create or upgrade the tables.
	 */
	public static function install(): void {
		global $wpdb;
		require_once ABSPATH . 'wp-admin/includes/upgrade.php';
		dbDelta( self::statements( $wpdb->get_charset_collate() ) );
		update_option( self::VERSION_OPTION, self::VERSION );
	}
}
