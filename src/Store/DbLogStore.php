<?php
/**
 * Lockout log in a custom table.
 *
 * @package Saizul\LoginLimit
 */

namespace Saizul\LoginLimit\Store;

use Saizul\LoginLimit\Schema;

defined( 'ABSPATH' ) || exit;

// phpcs:disable WordPress.DB.DirectDatabaseQuery -- Custom table, written on lockouts only.

/**
 * `{$wpdb->prefix}login_limit_log` table.
 */
final class DbLogStore implements LogStore {

	/**
	 * {@inheritDoc}
	 *
	 * @param array<string,mixed> $entry Entry.
	 */
	public function add( array $entry ): void {
		global $wpdb;
		$wpdb->insert(
			Schema::log_table(),
			array(
				'created_at' => (int) ( $entry['time'] ?? time() ),
				'event'      => substr( (string) ( $entry['event'] ?? '' ), 0, 20 ),
				'ip'         => substr( (string) ( $entry['ip'] ?? '' ), 0, 64 ),
				'username'   => substr( (string) ( $entry['username'] ?? '' ), 0, 100 ),
				'gateway'    => substr( (string) ( $entry['gateway'] ?? '' ), 0, 20 ),
				'duration'   => (int) ( $entry['duration'] ?? 0 ),
				'level'      => (int) ( $entry['level'] ?? 0 ),
			),
			array( '%d', '%s', '%s', '%s', '%s', '%d', '%d' )
		);
	}

	/**
	 * {@inheritDoc}
	 *
	 * @param int $limit  Entries.
	 * @param int $offset Offset.
	 */
	public function recent( int $limit, int $offset = 0 ): array {
		global $wpdb;
		$rows = $wpdb->get_results(
			$wpdb->prepare( 'SELECT * FROM %i ORDER BY created_at DESC, id DESC LIMIT %d OFFSET %d', Schema::log_table(), max( 1, $limit ), max( 0, $offset ) ),
			ARRAY_A
		);
		if ( ! is_array( $rows ) ) {
			return array();
		}

		return array_map(
			static function ( array $row ) {
				$row['time'] = (int) $row['created_at'];
				return $row;
			},
			$rows
		);
	}

	/**
	 * {@inheritDoc}
	 */
	public function count(): int {
		global $wpdb;

		return (int) $wpdb->get_var( $wpdb->prepare( 'SELECT COUNT(*) FROM %i', Schema::log_table() ) );
	}

	/**
	 * {@inheritDoc}
	 */
	public function clear(): void {
		global $wpdb;
		$wpdb->query( $wpdb->prepare( 'TRUNCATE TABLE %i', Schema::log_table() ) );
	}

	/**
	 * {@inheritDoc}
	 *
	 * @param int $before Time.
	 */
	public function purge( int $before ): int {
		global $wpdb;

		return (int) $wpdb->query( $wpdb->prepare( 'DELETE FROM %i WHERE created_at < %d', Schema::log_table(), $before ) );
	}
}
