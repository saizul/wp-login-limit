<?php
/**
 * A lockout or a denied request.
 *
 * @package Saizul\LoginLimit
 */

namespace Saizul\LoginLimit;

defined( 'ABSPATH' ) || exit;

/**
 * Why a login attempt is (or was just) blocked.
 */
final class Lockout {

	const REASON_IP       = 'ip';
	const REASON_USER     = 'user';
	const REASON_DENYLIST = 'denylist';

	/**
	 * One of the REASON_* constants.
	 *
	 * @var string
	 */
	public $reason;

	/**
	 * Locked until (0 for the denylist: no end).
	 *
	 * @var int
	 */
	public $until;

	/**
	 * Lockout duration in seconds (0 for the denylist).
	 *
	 * @var int
	 */
	public $duration;

	/**
	 * Escalation level (1 = first lockout).
	 *
	 * @var int
	 */
	public $level;

	/**
	 * Client IP.
	 *
	 * @var string
	 */
	public $ip;

	/**
	 * Username tried (normalised).
	 *
	 * @var string
	 */
	public $username;

	/**
	 * Login gateway: login, xmlrpc or rest.
	 *
	 * @var string
	 */
	public $gateway;

	/**
	 * Constructor.
	 *
	 * @param string $reason   Reason.
	 * @param int    $until    Locked until.
	 * @param int    $duration Duration.
	 * @param int    $level    Level.
	 * @param string $ip       IP.
	 * @param string $username Username.
	 * @param string $gateway  Gateway.
	 */
	public function __construct( string $reason, int $until, int $duration, int $level, string $ip, string $username, string $gateway = '' ) {
		$this->reason   = $reason;
		$this->until    = $until;
		$this->duration = $duration;
		$this->level    = $level;
		$this->ip       = $ip;
		$this->username = $username;
		$this->gateway  = $gateway;
	}

	/**
	 * Seconds left at `$now` (0 for the denylist).
	 *
	 * @param int $now Current time.
	 */
	public function remaining( int $now ): int {
		return max( 0, $this->until - $now );
	}
}
