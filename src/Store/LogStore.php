<?php
/**
 * Lockout log storage contract.
 *
 * @package Saizul\LoginLimit
 */

namespace Saizul\LoginLimit\Store;

defined( 'ABSPATH' ) || exit;

/**
 * Lockout log: lockouts, denied requests and unlocks.
 */
interface LogStore {

	/**
	 * Add an entry.
	 *
	 * @param array<string,mixed> $entry time (int), event, ip, username, gateway, duration (int), level (int).
	 */
	public function add( array $entry ): void;

	/**
	 * Latest entries first.
	 *
	 * @param int $limit  Entries.
	 * @param int $offset Offset.
	 * @return array<int,array<string,mixed>>
	 */
	public function recent( int $limit, int $offset = 0 ): array;

	/**
	 * Number of entries.
	 */
	public function count(): int;

	/**
	 * Delete every entry.
	 */
	public function clear(): void;

	/**
	 * Delete entries older than `$before`.
	 *
	 * @param int $before Time.
	 * @return int Entries deleted.
	 */
	public function purge( int $before ): int;
}
