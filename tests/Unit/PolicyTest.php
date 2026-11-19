<?php
declare(strict_types=1);

namespace Saizul\LoginLimit\Tests\Unit;

use PHPUnit\Framework\TestCase;
use Saizul\LoginLimit\Policy;
use Saizul\LoginLimit\Record;
use Saizul\LoginLimit\Settings;

/**
 * Lockout math: windows, escalation, caps, memory.
 */
final class PolicyTest extends TestCase {

	const T = 1800000000;

	private static function record(): Record {
		return new Record( Record::KIND_IP, '203.0.113.5' );
	}

	public function test_default_escalation_15m_1h_4h_16h_then_24h(): void {
		$policy = Policy::from_settings( Settings::defaults() );

		self::assertSame( 900, $policy->duration( 1 ) );
		self::assertSame( 3600, $policy->duration( 2 ) );
		self::assertSame( 14400, $policy->duration( 3 ) );
		self::assertSame( 57600, $policy->duration( 4 ) );
		self::assertSame( 86400, $policy->duration( 5 ) );
		self::assertSame( 86400, $policy->duration( 50 ) );
		self::assertSame( 900, $policy->duration( 0 ) );
	}

	public function test_multiplier_one_means_no_escalation(): void {
		$policy = new Policy( 900, 600, 1, 86400, 86400 );

		self::assertSame( 600, $policy->duration( 1 ) );
		self::assertSame( 600, $policy->duration( 9 ) );
	}

	public function test_huge_levels_do_not_overflow(): void {
		$policy = new Policy( 900, 604800, 10, 2592000, 86400 );

		self::assertSame( 2592000, $policy->duration( PHP_INT_MAX ) );
	}

	public function test_lockout_after_limit_failures(): void {
		$policy = new Policy();
		$record = self::record();

		for ( $i = 1; $i <= 4; $i++ ) {
			self::assertSame( 0, $policy->fail( $record, 5, self::T + $i ) );
		}
		self::assertSame( 1, $policy->remaining( $record, 5, self::T + 5 ) );
		self::assertSame( 900, $policy->fail( $record, 5, self::T + 5 ) );
		self::assertTrue( $record->is_locked( self::T + 5 ) );
		self::assertSame( self::T + 905, $record->locked_until );
		self::assertSame( 1, $record->lockouts );
		self::assertSame( 0, $record->failures );
		self::assertSame( 0, $policy->remaining( $record, 5, self::T + 6 ) );
	}

	public function test_failures_while_locked_are_not_counted(): void {
		$policy = new Policy();
		$record = self::record();
		for ( $i = 0; $i < 5; $i++ ) {
			$policy->fail( $record, 5, self::T );
		}
		for ( $i = 0; $i < 20; $i++ ) {
			self::assertSame( 0, $policy->fail( $record, 5, self::T + 10 ) );
		}

		self::assertSame( 0, $record->failures );
		self::assertSame( 1, $record->lockouts );
		self::assertSame( self::T + 900, $record->locked_until );
	}

	public function test_window_resets_the_counter(): void {
		$policy = new Policy( 900 );
		$record = self::record();
		for ( $i = 0; $i < 4; $i++ ) {
			$policy->fail( $record, 5, self::T );
		}

		self::assertSame( 0, $policy->fail( $record, 5, self::T + 900 ) );
		self::assertSame( 1, $record->failures );
		self::assertSame( self::T + 900, $record->window_start );
		self::assertSame( 5, $policy->remaining( $record, 5, self::T + 1800 ) );
	}

	public function test_window_is_fixed_from_the_first_failure(): void {
		$policy = new Policy( 900 );
		$record = self::record();
		$policy->fail( $record, 3, self::T );
		$policy->fail( $record, 3, self::T + 899 );

		self::assertSame( 900, $policy->fail( $record, 3, self::T + 899 ) );
	}

	public function test_second_lockout_escalates_and_memory_resets_it(): void {
		$policy = new Policy( 900, 900, 4, 86400, 86400 );
		$record = self::record();
		$t      = self::T;

		$lock = static function () use ( $policy, $record, &$t ): int {
			$duration = 0;
			for ( $i = 0; $i < 5; $i++ ) {
				$duration = $policy->fail( $record, 5, $t );
			}
			return $duration;
		};

		self::assertSame( 900, $lock() );
		$t += 900;
		self::assertSame( 3600, $lock() );
		$t += 3600;
		self::assertSame( 14400, $lock() );
		self::assertSame( 3, $record->lockouts );

		$t += 14400 + 86400;
		self::assertSame( 900, $lock() );
		self::assertSame( 1, $record->lockouts );
	}

	public function test_lock_directly(): void {
		$policy = new Policy();
		$record = self::record();

		self::assertSame( 900, $policy->lock( $record, self::T ) );
		self::assertSame( 3600, $policy->lock( $record, self::T + 1000 ) );
		self::assertSame( self::T + 1000 + 3600, $record->locked_until );
	}

	public function test_limit_zero_disables(): void {
		$policy = new Policy();
		$record = self::record();
		for ( $i = 0; $i < 100; $i++ ) {
			self::assertSame( 0, $policy->fail( $record, 0, self::T ) );
		}

		self::assertSame( 0, $record->failures );
		self::assertSame( PHP_INT_MAX, $policy->remaining( $record, 0, self::T ) );
	}

	public function test_limit_one_locks_on_the_first_failure(): void {
		self::assertSame( 900, ( new Policy() )->fail( self::record(), 1, self::T ) );
	}

	public function test_constructor_clamps(): void {
		$policy = new Policy( 0, 0, 0, 0, 0 );

		self::assertSame( 1, $policy->window );
		self::assertSame( 1, $policy->base );
		self::assertSame( 1, $policy->multiplier );
		self::assertSame( 1, $policy->max );
		self::assertSame( 1, $policy->memory );
		self::assertSame( 3600, ( new Policy( 900, 3600, 2, 60 ) )->duration( 3 ) );
	}

	public function test_is_stale(): void {
		$policy = new Policy( 900, 900, 4, 86400, 86400 );
		$record = self::record();
		self::assertTrue( $policy->is_stale( $record, self::T ) );

		$policy->fail( $record, 5, self::T );
		self::assertFalse( $policy->is_stale( $record, self::T + 10 ) );
		self::assertTrue( $policy->is_stale( $record, self::T + 900 ) );

		$policy->lock( $record, self::T + 1000 );
		self::assertFalse( $policy->is_stale( $record, self::T + 2000 ) );
		self::assertFalse( $policy->is_stale( $record, self::T + 1000 + 3600 ) );
		self::assertTrue( $policy->is_stale( $record, self::T + 1000 + 86400 ) );
	}

	public function test_record_round_trip(): void {
		$record           = self::record();
		$record->failures = 3;
		$record->lockouts = 2;
		$copy             = Record::from_array( $record->to_array() );

		self::assertSame( $record->to_array(), $copy->to_array() );
		self::assertSame( 'ip:203.0.113.5', $copy->key() );
		self::assertSame( 'user:admin', Record::make_key( Record::KIND_USER, 'admin' ) );
	}
}
