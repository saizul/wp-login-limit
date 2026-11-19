<?php
/**
 * Attempts in a custom table.
 *
 * @package Saizul\LoginLimit
 */

namespace Saizul\LoginLimit\Store;

use Saizul\LoginLimit\Record;
use Saizul\LoginLimit\Schema;

defined( 'ABSPATH' ) || exit;

// phpcs:disable WordPress.DB.DirectDatabaseQuery -- Security counters must not be cached: an object cache could hide a failure.

/**
 * `{$wpdb->prefix}login_limit_attempts` table, keyed by `kind:value`.
 */
final class DbAttemptStore implements AttemptStore {

	/**
	 * {@inheritDoc}
	 *
	 * @param string $key Key.
	 */
	public function get( string $key ): ?Record {
		global $wpdb;
		$row = $wpdb->get_row( $wpdb->prepare( 'SELECT * FROM %i WHERE lock_key = %s', Schema::attempts_table(), $key ), ARRAY_A );

		return is_array( $row ) ? Record::from_array( $row ) : null;
	}

	/**
	 * {@inheritDoc}
	 *
	 * @param Record $record Record.
	 * @param int    $now    Current time.
	 */
	public function put( Record $record, int $now ): void {
		global $wpdb;
		$wpdb->replace(
			Schema::attempts_table(),
			array(
				'lock_key'     => $record->key(),
				'kind'         => $record->kind,
				'value'        => $record->value,
				'failures'     => $record->failures,
				'window_start' => $record->window_start,
				'lockouts'     => $record->lockouts,
				'locked_until' => $record->locked_until,
				'last_lockout' => $record->last_lockout,
				'updated_at'   => $now,
			),
			array( '%s', '%s', '%s', '%d', '%d', '%d', '%d', '%d', '%d' )
		);
	}

	/**
	 * {@inheritDoc}
	 *
	 * @param string $key Key.
	 */
	public function delete( string $key ): bool {
		global $wpdb;

		return (bool) $wpdb->delete( Schema::attempts_table(), array( 'lock_key' => $key ), array( '%s' ) );
	}

	/**
	 * {@inheritDoc}
	 */
	public function delete_all(): int {
		global $wpdb;

		return (int) $wpdb->query( $wpdb->prepare( 'DELETE FROM %i', Schema::attempts_table() ) );
	}

	/**
	 * {@inheritDoc}
	 *
	 * @param int $now Current time.
	 */
	public function locked( int $now ): array {
		global $wpdb;
		$rows = $wpdb->get_results( $wpdb->prepare( 'SELECT * FROM %i WHERE locked_until > %d ORDER BY last_lockout DESC LIMIT 500', Schema::attempts_table(), $now ), ARRAY_A );

		return array_map( array( Record::class, 'from_array' ), is_array( $rows ) ? $rows : array() );
	}

	/**
	 * {@inheritDoc}
	 *
	 * @param int $before Time.
	 * @param int $now    Current time.
	 */
	public function purge( int $before, int $now ): int {
		global $wpdb;

		return (int) $wpdb->query( $wpdb->prepare( 'DELETE FROM %i WHERE updated_at < %d AND locked_until <= %d', Schema::attempts_table(), $before, $now ) );
	}
}
