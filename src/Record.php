<?php
/**
 * Failure and lockout state of one IP or username.
 *
 * @package Saizul\LoginLimit
 */

namespace Saizul\LoginLimit;

defined( 'ABSPATH' ) || exit;

/**
 * Plain data, changed only by Policy. Times are Unix timestamps.
 */
final class Record {

	const KIND_IP   = 'ip';
	const KIND_USER = 'user';

	/**
	 * `ip` or `user`.
	 *
	 * @var string
	 */
	public $kind = self::KIND_IP;

	/**
	 * IP address or network, or lower-case username.
	 *
	 * @var string
	 */
	public $value = '';

	/**
	 * Failures in the current window.
	 *
	 * @var int
	 */
	public $failures = 0;

	/**
	 * Start of the current counting window.
	 *
	 * @var int
	 */
	public $window_start = 0;

	/**
	 * Escalation level: lockouts since the memory period last expired.
	 *
	 * @var int
	 */
	public $lockouts = 0;

	/**
	 * Locked until this time (0 when not locked).
	 *
	 * @var int
	 */
	public $locked_until = 0;

	/**
	 * Time of the last lockout.
	 *
	 * @var int
	 */
	public $last_lockout = 0;

	/**
	 * Constructor.
	 *
	 * @param string $kind  `ip` or `user`.
	 * @param string $value Address, network or username.
	 */
	public function __construct( string $kind, string $value ) {
		$this->kind  = $kind;
		$this->value = $value;
	}

	/**
	 * Storage key, for example `ip:203.0.113.5` or `user:admin`.
	 */
	public function key(): string {
		return self::make_key( $this->kind, $this->value );
	}

	/**
	 * Storage key for a kind and value.
	 *
	 * @param string $kind  `ip` or `user`.
	 * @param string $value Value.
	 */
	public static function make_key( string $kind, string $value ): string {
		return $kind . ':' . $value;
	}

	/**
	 * Whether the record is locked at `$now`.
	 *
	 * @param int $now Current time.
	 */
	public function is_locked( int $now ): bool {
		return $this->locked_until > $now;
	}

	/**
	 * Build from an array (database row or test data).
	 *
	 * @param array<string,mixed> $row Row.
	 */
	public static function from_array( array $row ): self {
		$record               = new self( (string) ( $row['kind'] ?? self::KIND_IP ), (string) ( $row['value'] ?? '' ) );
		$record->failures     = (int) ( $row['failures'] ?? 0 );
		$record->window_start = (int) ( $row['window_start'] ?? 0 );
		$record->lockouts     = (int) ( $row['lockouts'] ?? 0 );
		$record->locked_until = (int) ( $row['locked_until'] ?? 0 );
		$record->last_lockout = (int) ( $row['last_lockout'] ?? 0 );

		return $record;
	}

	/**
	 * Array form.
	 *
	 * @return array<string,mixed>
	 */
	public function to_array(): array {
		return array(
			'kind'         => $this->kind,
			'value'        => $this->value,
			'failures'     => $this->failures,
			'window_start' => $this->window_start,
			'lockouts'     => $this->lockouts,
			'locked_until' => $this->locked_until,
			'last_lockout' => $this->last_lockout,
		);
	}
}
