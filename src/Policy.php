<?php
/**
 * Lockout math.
 *
 * @package Saizul\LoginLimit
 */

namespace Saizul\LoginLimit;

defined( 'ABSPATH' ) || exit;

/**
 * Counting and escalation rules, as pure functions of a Record and the time.
 *
 * - Failures are counted in a fixed window that starts at the first failure
 *   and lasts `window` seconds. When the window has passed, counting starts
 *   again.
 * - Reaching `limit` failures locks the record. The n-th lockout lasts
 *   `base * multiplier^(n-1)` seconds, capped at `max`.
 * - The escalation level drops back to zero after `memory` seconds without a
 *   lockout.
 *
 * With the defaults (base 15 minutes, multiplier 4, max 24 hours) lockouts
 * last 15 min, 1 h, 4 h, 16 h, then 24 h.
 */
final class Policy {

	/**
	 * Counting window in seconds.
	 *
	 * @var int
	 */
	public $window;

	/**
	 * First lockout duration in seconds.
	 *
	 * @var int
	 */
	public $base;

	/**
	 * Growth factor for each further lockout.
	 *
	 * @var int
	 */
	public $multiplier;

	/**
	 * Longest lockout in seconds.
	 *
	 * @var int
	 */
	public $max;

	/**
	 * Seconds without a lockout after which escalation starts over.
	 *
	 * @var int
	 */
	public $memory;

	/**
	 * Constructor.
	 *
	 * @param int $window     Counting window in seconds.
	 * @param int $base       First lockout in seconds.
	 * @param int $multiplier Growth factor (1 = no escalation).
	 * @param int $max        Longest lockout in seconds.
	 * @param int $memory     Seconds after which escalation starts over.
	 */
	public function __construct( int $window = 900, int $base = 900, int $multiplier = 4, int $max = 86400, int $memory = 86400 ) {
		$this->window     = max( 1, $window );
		$this->base       = max( 1, $base );
		$this->multiplier = max( 1, $multiplier );
		$this->max        = max( $this->base, $max );
		$this->memory     = max( 1, $memory );
	}

	/**
	 * Build from the plugin settings.
	 *
	 * @param array<string,mixed> $settings Settings.
	 */
	public static function from_settings( array $settings ): self {
		return new self(
			(int) $settings['window'],
			(int) $settings['lockout_duration'],
			(int) $settings['lockout_multiplier'],
			(int) $settings['lockout_max'],
			(int) $settings['lockout_memory']
		);
	}

	/**
	 * Duration of the lockout at an escalation level (1 = first lockout).
	 *
	 * @param int $level Level, at least 1.
	 */
	public function duration( int $level ): int {
		$duration = $this->base;
		for ( $i = 1; $i < $level && $duration < $this->max; $i++ ) {
			$duration *= $this->multiplier;
		}

		return min( $this->max, $duration );
	}

	/**
	 * Count a failure. Returns the lockout duration when this failure locks
	 * the record, otherwise 0. Failures while locked are not counted.
	 *
	 * @param Record $record Record, changed in place.
	 * @param int    $limit  Failures allowed in a window; 0 disables the limit.
	 * @param int    $now    Current time.
	 */
	public function fail( Record $record, int $limit, int $now ): int {
		if ( $limit <= 0 || $record->is_locked( $now ) ) {
			return 0;
		}
		if ( 0 === $record->failures || $now - $record->window_start >= $this->window ) {
			$record->failures     = 0;
			$record->window_start = $now;
		}
		++$record->failures;
		if ( $record->failures < $limit ) {
			return 0;
		}

		return $this->lock( $record, $now );
	}

	/**
	 * Lock a record now, escalating from its previous lockouts.
	 *
	 * @param Record $record Record, changed in place.
	 * @param int    $now    Current time.
	 * @return int Lockout duration in seconds.
	 */
	public function lock( Record $record, int $now ): int {
		if ( $record->last_lockout > 0 && $now - $record->last_lockout >= $this->memory ) {
			$record->lockouts = 0;
		}
		++$record->lockouts;
		$duration             = $this->duration( $record->lockouts );
		$record->locked_until = $now + $duration;
		$record->last_lockout = $now;
		$record->failures     = 0;
		$record->window_start = 0;

		return $duration;
	}

	/**
	 * Failures left before a lockout.
	 *
	 * @param Record $record Record.
	 * @param int    $limit  Failures allowed in a window.
	 * @param int    $now    Current time.
	 */
	public function remaining( Record $record, int $limit, int $now ): int {
		if ( $limit <= 0 ) {
			return PHP_INT_MAX;
		}
		if ( $record->is_locked( $now ) ) {
			return 0;
		}
		$failures = $now - $record->window_start >= $this->window ? 0 : $record->failures;

		return max( 0, $limit - $failures );
	}

	/**
	 * Whether a record holds nothing worth keeping at `$now` (for clean-up).
	 *
	 * @param Record $record Record.
	 * @param int    $now    Current time.
	 */
	public function is_stale( Record $record, int $now ): bool {
		return ! $record->is_locked( $now )
			&& ( 0 === $record->failures || $now - $record->window_start >= $this->window )
			&& ( 0 === $record->last_lockout || $now - $record->last_lockout >= $this->memory );
	}
}
