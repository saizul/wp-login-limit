<?php
/**
 * Brute-force limiter.
 *
 * @package Saizul\LoginLimit
 */

namespace Saizul\LoginLimit;

use Saizul\LoginLimit\Store\AttemptStore;
use Saizul\LoginLimit\Store\LogStore;

defined( 'ABSPATH' ) || exit;

/**
 * Applies the allowlist, the denylist, the per-IP and per-username limits and
 * the lockout policy. Knows nothing about WordPress hooks; Auth calls it.
 */
final class Limiter {

	const MAX_USERNAME = 100;

	/**
	 * Attempt storage.
	 *
	 * @var AttemptStore
	 */
	private $attempts;

	/**
	 * Lockout log.
	 *
	 * @var LogStore
	 */
	private $log;

	/**
	 * Settings.
	 *
	 * @var array<string,mixed>
	 */
	private $settings;

	/**
	 * Lockout math.
	 *
	 * @var Policy
	 */
	private $policy;

	/**
	 * Returns the current time.
	 *
	 * @var callable
	 */
	private $clock;

	/**
	 * Constructor.
	 *
	 * @param AttemptStore        $attempts Attempt storage.
	 * @param LogStore            $log      Lockout log.
	 * @param array<string,mixed> $settings Settings (Settings::get()).
	 * @param callable|null       $clock    Returns the current Unix time (tests).
	 */
	public function __construct( AttemptStore $attempts, LogStore $log, array $settings, ?callable $clock = null ) {
		$this->attempts = $attempts;
		$this->log      = $log;
		$this->settings = array_merge( Settings::defaults(), $settings );
		$this->policy   = Policy::from_settings( $this->settings );
		$this->clock    = $clock ?? 'time';
	}

	/**
	 * Current time.
	 */
	public function now(): int {
		return (int) call_user_func( $this->clock );
	}

	/**
	 * Lockout policy.
	 */
	public function policy(): Policy {
		return $this->policy;
	}

	/**
	 * Settings in use.
	 *
	 * @return array<string,mixed>
	 */
	public function settings(): array {
		return $this->settings;
	}

	/**
	 * Username as counted: trimmed, lower case, no control characters, at most 100 characters.
	 *
	 * @param string $username Raw username or email.
	 */
	public static function normalize_username( string $username ): string {
		$username = trim( (string) preg_replace( '/[\x00-\x1F\x7F]/', '', $username ) );
		if ( function_exists( 'mb_strtolower' ) ) {
			return mb_substr( mb_strtolower( $username, 'UTF-8' ), 0, self::MAX_USERNAME, 'UTF-8' );
		}

		return substr( strtolower( $username ), 0, self::MAX_USERNAME );
	}

	/**
	 * Key value for an IP: the address, or its IPv6 network.
	 *
	 * @param string $ip Address.
	 */
	public function network( string $ip ): string {
		return Ip::network( $ip, (int) $this->settings['ipv6_prefix'] );
	}

	/**
	 * Whether the IP is on the allowlist (never counted, never locked).
	 *
	 * @param string $ip Address.
	 */
	public function is_allowlisted( string $ip ): bool {
		return '' !== $ip && Ip::matches( $ip, (array) $this->settings['allowlist'] );
	}

	/**
	 * Whether the IP is on the denylist (never allowed to log in).
	 *
	 * @param string $ip Address.
	 */
	public function is_denylisted( string $ip ): bool {
		return '' !== $ip && ! $this->is_allowlisted( $ip ) && Ip::matches( $ip, (array) $this->settings['denylist'] );
	}

	/**
	 * Whether trying this username locks the IP at once.
	 *
	 * @param string $username Normalised username.
	 */
	public function is_denied_username( string $username ): bool {
		return '' !== $username && in_array( $username, (array) $this->settings['deny_usernames'], true );
	}

	/**
	 * Whether a login attempt must be refused before the password is checked.
	 *
	 * @param string   $ip       Client IP.
	 * @param string   $username Normalised username (may be empty).
	 * @param string[] $known    IP networks this user logged in from before;
	 *                           a username lockout does not apply to them.
	 */
	public function check( string $ip, string $username, array $known = array() ): ?Lockout {
		if ( $this->is_allowlisted( $ip ) ) {
			return null;
		}
		if ( $this->is_denylisted( $ip ) ) {
			return new Lockout( Lockout::REASON_DENYLIST, 0, 0, 0, $ip, $username );
		}
		$now = $this->now();
		if ( '' !== $ip ) {
			$record = $this->attempts->get( Record::make_key( Record::KIND_IP, $this->network( $ip ) ) );
			if ( null !== $record && $record->is_locked( $now ) ) {
				return new Lockout( Lockout::REASON_IP, $record->locked_until, $record->locked_until - $record->last_lockout, $record->lockouts, $ip, $username );
			}
		}
		if ( '' !== $username && (int) $this->settings['user_max_retries'] > 0 && ! in_array( $this->network( $ip ), $known, true ) ) {
			$record = $this->attempts->get( Record::make_key( Record::KIND_USER, $username ) );
			if ( null !== $record && $record->is_locked( $now ) ) {
				return new Lockout( Lockout::REASON_USER, $record->locked_until, $record->locked_until - $record->last_lockout, $record->lockouts, $ip, $username );
			}
		}

		return null;
	}

	/**
	 * Count a failed login. Returns the lockout this failure caused, if any
	 * (the IP lockout when both the IP and the username were locked).
	 *
	 * @param string $ip       Client IP.
	 * @param string $username Normalised username.
	 * @param string $gateway  login, xmlrpc or rest.
	 */
	public function fail( string $ip, string $username, string $gateway ): ?Lockout {
		if ( $this->is_allowlisted( $ip ) ) {
			return null;
		}
		$now      = $this->now();
		$lockouts = array();

		if ( '' !== $ip ) {
			$network = $this->network( $ip );
			$record  = $this->attempts->get( Record::make_key( Record::KIND_IP, $network ) ) ?? new Record( Record::KIND_IP, $network );
			if ( $this->is_denied_username( $username ) && ! $record->is_locked( $now ) ) {
				$duration = $this->policy->lock( $record, $now );
			} else {
				$duration = $this->policy->fail( $record, (int) $this->settings['ip_max_retries'], $now );
			}
			$this->attempts->put( $record, $now );
			if ( $duration > 0 ) {
				$lockouts[] = new Lockout( Lockout::REASON_IP, $record->locked_until, $duration, $record->lockouts, $ip, $username, $gateway );
			}
		}

		if ( '' !== $username && (int) $this->settings['user_max_retries'] > 0 ) {
			$record   = $this->attempts->get( Record::make_key( Record::KIND_USER, $username ) ) ?? new Record( Record::KIND_USER, $username );
			$duration = $this->policy->fail( $record, (int) $this->settings['user_max_retries'], $now );
			$this->attempts->put( $record, $now );
			if ( $duration > 0 ) {
				$lockouts[] = new Lockout( Lockout::REASON_USER, $record->locked_until, $duration, $record->lockouts, $ip, $username, $gateway );
			}
		}

		foreach ( $lockouts as $lockout ) {
			$this->log->add(
				array(
					'time'     => $now,
					'event'    => 'lockout_' . $lockout->reason,
					'ip'       => $ip,
					'username' => $username,
					'gateway'  => $gateway,
					'duration' => $lockout->duration,
					'level'    => $lockout->level,
				)
			);
		}

		return $lockouts[0] ?? null;
	}

	/**
	 * Successful login: forget the failures of this IP and username (the
	 * escalation level stays until the memory period passes).
	 *
	 * @param string $ip       Client IP.
	 * @param string $username Normalised username.
	 */
	public function success( string $ip, string $username ): void {
		$now  = $this->now();
		$keys = array();
		if ( '' !== $ip ) {
			$keys[] = Record::make_key( Record::KIND_IP, $this->network( $ip ) );
		}
		if ( '' !== $username ) {
			$keys[] = Record::make_key( Record::KIND_USER, $username );
		}
		foreach ( $keys as $key ) {
			$record = $this->attempts->get( $key );
			if ( null !== $record && $record->failures > 0 && ! $record->is_locked( $now ) ) {
				$record->failures     = 0;
				$record->window_start = 0;
				$this->attempts->put( $record, $now );
			}
		}
	}

	/**
	 * Log a refused attempt (denylist or an attempt during a lockout).
	 *
	 * @param Lockout $lockout  Why it was refused.
	 * @param string  $gateway  Gateway.
	 */
	public function log_denied( Lockout $lockout, string $gateway ): void {
		if ( Lockout::REASON_DENYLIST !== $lockout->reason ) {
			return;
		}
		$this->log->add(
			array(
				'time'     => $this->now(),
				'event'    => 'denied',
				'ip'       => $lockout->ip,
				'username' => $lockout->username,
				'gateway'  => $gateway,
			)
		);
	}

	/**
	 * Remove lockouts and counters for an IP (or its network) or a username.
	 *
	 * @param string $target IP address, IPv6 network or username.
	 * @return int Records removed (0 or 1).
	 */
	public function unlock( string $target ): int {
		$target = trim( $target );
		if ( '' === $target ) {
			return 0;
		}
		if ( Ip::is_valid( $target ) ) {
			$key = Record::make_key( Record::KIND_IP, $this->network( $target ) );
		} elseif ( preg_match( '#^[0-9a-fA-F:]+/\d{1,3}$#', $target ) ) {
			$key = Record::make_key( Record::KIND_IP, (string) Ip::normalize_entry( $target ) );
		} else {
			$key = Record::make_key( Record::KIND_USER, self::normalize_username( $target ) );
		}
		return $this->unlock_key( $key ) ? 1 : 0;
	}

	/**
	 * Remove the lockout and counters of one record key (`ip:...` or `user:...`).
	 *
	 * @param string $key Record key.
	 */
	public function unlock_key( string $key ): bool {
		if ( 0 !== strpos( $key, 'ip:' ) && 0 !== strpos( $key, 'user:' ) ) {
			return false;
		}
		$done = $this->attempts->delete( $key );
		if ( $done ) {
			$this->log->add(
				array(
					'time'     => $this->now(),
					'event'    => 'unlock',
					'ip'       => 0 === strpos( $key, 'ip:' ) ? substr( $key, 3 ) : '',
					'username' => 0 === strpos( $key, 'user:' ) ? substr( $key, 5 ) : '',
				)
			);
		}

		return $done;
	}

	/**
	 * Remove every lockout and counter.
	 *
	 * @return int Records removed.
	 */
	public function unlock_all(): int {
		$count = $this->attempts->delete_all();
		$this->log->add(
			array(
				'time'  => $this->now(),
				'event' => 'unlock_all',
			)
		);

		return $count;
	}

	/**
	 * Active lockouts.
	 *
	 * @return Record[]
	 */
	public function locked(): array {
		return $this->attempts->locked( $this->now() );
	}

	/**
	 * Delete stale counters and old log entries.
	 *
	 * @return int Rows deleted.
	 */
	public function purge(): int {
		$now  = $this->now();
		$keep = max( (int) $this->settings['window'], (int) $this->settings['lockout_memory'] );

		return $this->attempts->purge( $now - $keep, $now ) + $this->log->purge( $now - (int) $this->settings['log_retention_days'] * DAY_IN_SECONDS );
	}
}
