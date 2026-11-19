<?php
declare(strict_types=1);

namespace Saizul\LoginLimit\Tests\Unit;

use Saizul\LoginLimit\Limiter;
use Saizul\LoginLimit\Lockout;
use Saizul\LoginLimit\Tests\WpTestCase;

/**
 * Per-IP and per-username limits, lists, unlocking and clean-up.
 */
final class LimiterTest extends WpTestCase {

	private function limiter(): Limiter {
		return $this->plugin->limiter();
	}

	private function fail_times( int $times, string $ip, string $user = 'admin' ): ?Lockout {
		$lockout = null;
		for ( $i = 0; $i < $times; $i++ ) {
			$lockout = $this->limiter()->fail( $ip, $user, 'login' ) ?? $lockout;
		}
		return $lockout;
	}

	public function test_ip_is_locked_after_five_failures(): void {
		self::assertNull( $this->fail_times( 4, '203.0.113.5' ) );
		self::assertNull( $this->limiter()->check( '203.0.113.5', 'admin' ) );

		$lockout = $this->fail_times( 1, '203.0.113.5' );
		self::assertNotNull( $lockout );
		self::assertSame( Lockout::REASON_IP, $lockout->reason );
		self::assertSame( 900, $lockout->duration );
		self::assertSame( 1, $lockout->level );
		self::assertSame( 'login', $lockout->gateway );
		self::assertSame( self::NOW + 900, $lockout->until );

		$check = $this->limiter()->check( '203.0.113.5', 'someone-else' );
		self::assertNotNull( $check );
		self::assertSame( 900, $check->remaining( $this->now ) );
		self::assertNull( $this->limiter()->check( '203.0.113.6', 'admin' ) );
		self::assertSame( array( 'lockout_ip' ), $this->log->events() );
	}

	public function test_lockout_expires(): void {
		$this->fail_times( 5, '203.0.113.5' );
		$this->now += 900;

		self::assertNull( $this->limiter()->check( '203.0.113.5', 'admin' ) );
	}

	public function test_second_lockout_escalates(): void {
		$this->fail_times( 5, '203.0.113.5' );
		$this->now += 901;
		$lockout = $this->fail_times( 5, '203.0.113.5' );

		self::assertSame( 3600, $lockout->duration );
		self::assertSame( 2, $lockout->level );
	}

	public function test_ipv6_addresses_in_one_64_share_a_counter(): void {
		for ( $i = 1; $i <= 5; $i++ ) {
			$this->limiter()->fail( '2001:db8:1:2::' . dechex( $i ), 'u' . $i, 'login' );
		}

		self::assertNotNull( $this->limiter()->check( '2001:db8:1:2:ffff::1', '' ) );
		self::assertNull( $this->limiter()->check( '2001:db8:1:3::1', '' ) );
		self::assertArrayHasKey( 'ip:2001:db8:1:2::/64', $this->attempts->rows );
	}

	public function test_username_is_locked_across_ips(): void {
		self::settings( array( 'ip_max_retries' => 100, 'user_max_retries' => 3 ) );
		$this->limiter()->fail( '198.51.100.1', 'admin', 'xmlrpc' );
		$this->limiter()->fail( '198.51.100.2', 'admin', 'xmlrpc' );
		$lockout = $this->limiter()->fail( '198.51.100.3', 'admin', 'xmlrpc' );

		self::assertSame( Lockout::REASON_USER, $lockout->reason );
		$check = $this->limiter()->check( '198.51.100.99', 'admin' );
		self::assertSame( Lockout::REASON_USER, $check->reason );
		self::assertNull( $this->limiter()->check( '198.51.100.99', 'editor' ) );
		self::assertSame( array( 'lockout_user' ), $this->log->events() );
	}

	public function test_known_networks_bypass_a_username_lockout(): void {
		self::settings( array( 'ip_max_retries' => 100, 'user_max_retries' => 2 ) );
		$this->limiter()->fail( '198.51.100.1', 'admin', 'login' );
		$this->limiter()->fail( '198.51.100.2', 'admin', 'login' );

		self::assertNotNull( $this->limiter()->check( '192.0.2.50', 'admin' ) );
		self::assertNull( $this->limiter()->check( '192.0.2.50', 'admin', array( '192.0.2.50' ) ) );
	}

	public function test_username_limit_zero_disables_it(): void {
		self::settings( array( 'ip_max_retries' => 100, 'user_max_retries' => 0 ) );
		for ( $i = 0; $i < 50; $i++ ) {
			$this->limiter()->fail( '198.51.100.' . $i, 'admin', 'login' );
		}

		self::assertNull( $this->limiter()->check( '198.51.100.200', 'admin' ) );
		self::assertArrayNotHasKey( 'user:admin', $this->attempts->rows );
	}

	public function test_ip_and_username_lockout_together_reports_the_ip(): void {
		self::settings( array( 'ip_max_retries' => 2, 'user_max_retries' => 2 ) );
		$this->limiter()->fail( '198.51.100.1', 'admin', 'login' );
		$lockout = $this->limiter()->fail( '198.51.100.1', 'admin', 'login' );

		self::assertSame( Lockout::REASON_IP, $lockout->reason );
		self::assertSame( array( 'lockout_ip', 'lockout_user' ), $this->log->events() );
	}

	public function test_allowlist_is_never_counted(): void {
		self::settings( array( 'allowlist' => array( '192.0.2.0/24' ), 'denylist' => array( '192.0.2.0/24' ) ) );
		self::assertNull( $this->fail_times( 50, '192.0.2.10' ) );

		self::assertNull( $this->limiter()->check( '192.0.2.10', 'admin' ) );
		self::assertFalse( $this->limiter()->is_denylisted( '192.0.2.10' ) );
		self::assertSame( array(), $this->attempts->rows );
	}

	public function test_allowlisted_ip_ignores_username_lockouts(): void {
		self::settings( array( 'user_max_retries' => 1, 'allowlist' => array( '192.0.2.10' ) ) );
		$this->limiter()->fail( '198.51.100.1', 'admin', 'login' );

		self::assertNull( $this->limiter()->check( '192.0.2.10', 'admin' ) );
	}

	public function test_denylist(): void {
		self::settings( array( 'denylist' => array( '198.51.100.0/24', '2001:db8::/32' ) ) );

		self::assertSame( Lockout::REASON_DENYLIST, $this->limiter()->check( '198.51.100.7', '' )->reason );
		self::assertSame( Lockout::REASON_DENYLIST, $this->limiter()->check( '2001:db8::1', 'x' )->reason );
		self::assertNull( $this->limiter()->check( '198.51.101.7', '' ) );

		$this->limiter()->log_denied( $this->limiter()->check( '198.51.100.7', 'bob' ), 'rest' );
		self::assertSame( 'denied', $this->log->entries[0]['event'] );
		self::assertSame( 'rest', $this->log->entries[0]['gateway'] );
	}

	public function test_denied_username_locks_the_ip_at_once(): void {
		self::settings( array( 'deny_usernames' => array( 'admin', 'test' ) ) );
		$lockout = $this->limiter()->fail( '203.0.113.5', 'admin', 'login' );

		self::assertNotNull( $lockout );
		self::assertSame( Lockout::REASON_IP, $lockout->reason );
		self::assertTrue( $this->limiter()->is_denied_username( 'test' ) );
		self::assertFalse( $this->limiter()->is_denied_username( '' ) );
	}

	public function test_success_resets_failures_but_not_the_level(): void {
		$this->fail_times( 5, '203.0.113.5' );
		$this->now += 901;
		$this->fail_times( 3, '203.0.113.5' );
		$this->limiter()->success( '203.0.113.5', 'admin' );

		self::assertSame( 0, $this->attempts->rows['ip:203.0.113.5']['failures'] );
		self::assertSame( 1, $this->attempts->rows['ip:203.0.113.5']['lockouts'] );
		self::assertSame( 2, $this->fail_times( 5, '203.0.113.5' )->level );
	}

	public function test_success_does_not_lift_a_lockout(): void {
		$this->fail_times( 5, '203.0.113.5' );
		$this->limiter()->success( '203.0.113.5', 'admin' );

		self::assertNotNull( $this->limiter()->check( '203.0.113.5', 'admin' ) );
	}

	public function test_unlock_by_ip_network_and_username(): void {
		self::settings( array( 'user_max_retries' => 5 ) );
		$this->fail_times( 5, '203.0.113.5' );
		$this->fail_times( 5, '2001:db8:1:2::9', 'bob' );

		self::assertSame( 1, $this->limiter()->unlock( '203.0.113.5' ) );
		self::assertSame( 0, $this->limiter()->unlock( '203.0.113.5' ) );
		self::assertSame( 1, $this->limiter()->unlock( '2001:db8:1:2::/64' ) );
		self::assertSame( 1, $this->limiter()->unlock( ' Admin ' ) );
		self::assertSame( 0, $this->limiter()->unlock( '2001:db8:1:2::1234' ) );
		self::assertSame( 0, $this->limiter()->unlock( '' ) );
		self::assertFalse( $this->limiter()->unlock_key( 'other:thing' ) );
		self::assertNull( $this->limiter()->check( '203.0.113.5', 'admin' ) );
		self::assertContains( 'unlock', $this->log->events() );
	}

	public function test_unlock_all_and_locked_list(): void {
		$this->fail_times( 5, '203.0.113.5', 'a' );
		$this->now += 10;
		$this->fail_times( 5, '203.0.113.6', 'b' );

		$locked = $this->limiter()->locked();
		self::assertSame( array( '203.0.113.6', '203.0.113.5' ), array( $locked[0]->value, $locked[1]->value ) );
		self::assertGreaterThan( 0, $this->limiter()->unlock_all() );
		self::assertSame( array(), $this->limiter()->locked() );
		self::assertSame( 'unlock_all', end( $this->log->entries )['event'] );
	}

	public function test_purge_keeps_records_within_the_memory_period(): void {
		self::settings( array( 'log_retention_days' => 1 ) );
		$this->fail_times( 5, '203.0.113.5' );
		$this->fail_times( 1, '203.0.113.9' );
		$this->now += 3600;
		self::assertSame( 0, $this->limiter()->purge() );

		$this->now += 86400;
		self::assertSame( 4, $this->limiter()->purge() );
		self::assertSame( array(), $this->attempts->rows );
		self::assertSame( array(), $this->log->entries );
	}

	public function test_normalize_username(): void {
		self::assertSame( 'admin', Limiter::normalize_username( "  ADMIN\r\n" ) );
		self::assertSame( 'ünïcode', Limiter::normalize_username( 'ÜNÏCODE' ) );
		self::assertSame( 100, mb_strlen( Limiter::normalize_username( str_repeat( 'é', 300 ) ) ) );
	}

	public function test_empty_ip_counts_only_the_username(): void {
		self::settings( array( 'user_max_retries' => 2 ) );
		$this->limiter()->fail( '', 'admin', 'login' );
		$lockout = $this->limiter()->fail( '', 'admin', 'login' );

		self::assertSame( Lockout::REASON_USER, $lockout->reason );
		self::assertArrayNotHasKey( 'ip:', $this->attempts->rows );
	}
}
