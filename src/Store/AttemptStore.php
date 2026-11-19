<?php
/**
 * Attempt storage contract.
 *
 * @package Saizul\LoginLimit
 */

namespace Saizul\LoginLimit\Store;

use Saizul\LoginLimit\Record;

defined( 'ABSPATH' ) || exit;

/**
 * Failure counters and lockouts, one Record per IP or username. The database
 * implementation is DbAttemptStore; tests use an in-memory one.
 */
interface AttemptStore {

	/**
	 * Record for a key, or null.
	 *
	 * @param string $key Key such as `ip:203.0.113.5`.
	 */
	public function get( string $key ): ?Record;

	/**
	 * Insert or update a record.
	 *
	 * @param Record $record Record.
	 * @param int    $now    Current time (stored as last update).
	 */
	public function put( Record $record, int $now ): void;

	/**
	 * Delete a record.
	 *
	 * @param string $key Key.
	 * @return bool Whether a record was deleted.
	 */
	public function delete( string $key ): bool;

	/**
	 * Delete every record.
	 *
	 * @return int Records deleted.
	 */
	public function delete_all(): int;

	/**
	 * Records locked at `$now`, latest lockout first.
	 *
	 * @param int $now Current time.
	 * @return Record[]
	 */
	public function locked( int $now ): array;

	/**
	 * Delete records that are not locked and were last updated before `$before`.
	 *
	 * @param int $before Time.
	 * @param int $now    Current time.
	 * @return int Records deleted.
	 */
	public function purge( int $before, int $now ): int;
}
