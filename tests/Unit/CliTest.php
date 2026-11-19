<?php
declare(strict_types=1);

namespace Saizul\LoginLimit\Tests\Unit;

use Saizul\LoginLimit\Cli\Command;
use Saizul\LoginLimit\Tests\WpTestCase;
use WP_CLI;
use WpCliHalt;

/**
 * wp login-limit unlock|list|log|check.
 */
final class CliTest extends WpTestCase {

	/** @var Command */
	private $command;

	protected function setUp(): void {
		parent::setUp();
		$this->command = new Command( $this->plugin );
	}

	private function last( string $type ): string {
		$messages = array_values(
			array_filter(
				WP_CLI::$log,
				static function ( array $entry ) use ( $type ): bool {
					return $type === $entry[0];
				}
			)
		);
		return $messages ? (string) end( $messages )[1] : '';
	}

	private function lock( string $ip, string $user ): void {
		for ( $i = 0; $i < 5; $i++ ) {
			$this->plugin->limiter()->fail( $ip, $user, 'login' );
		}
	}

	public function test_unlock_targets(): void {
		$this->lock( '203.0.113.5', 'a' );
		$this->command->unlock( array( '203.0.113.5', 'nobody' ), array() );

		self::assertSame( 'Unlocked 203.0.113.5.', $this->last( 'line' ) );
		self::assertSame( 'Nothing to unlock for nobody.', $this->last( 'warning' ) );
		self::assertSame( 'Unlocked 1 of 2.', $this->last( 'success' ) );
	}

	public function test_unlock_all_and_errors(): void {
		$this->lock( '203.0.113.5', 'a' );
		$this->command->unlock( array(), array( 'all' => true ) );
		self::assertStringStartsWith( 'Removed ', $this->last( 'success' ) );
		self::assertSame( array(), $this->attempts->rows );

		$this->expectException( WpCliHalt::class );
		$this->command->unlock( array(), array() );
	}

	public function test_list_and_log(): void {
		$this->lock( '203.0.113.5', 'a' );
		$this->command->list_( array(), array( 'format' => 'json' ) );

		self::assertSame( 'json', WP_CLI::$items['format'] );
		self::assertSame( 'ip', WP_CLI::$items['items'][0]['type'] );
		self::assertSame( '203.0.113.5', WP_CLI::$items['items'][0]['value'] );
		self::assertSame( 900, WP_CLI::$items['items'][0]['seconds_left'] );

		$this->command->log( array(), array( 'limit' => '5' ) );
		self::assertSame( 'table', WP_CLI::$items['format'] );
		self::assertSame( 'lockout_ip', WP_CLI::$items['items'][0]['event'] );
		self::assertSame( 900, WP_CLI::$items['items'][0]['duration'] );
	}

	public function test_check(): void {
		$this->plugin->limiter()->fail( '203.0.113.5', 'a', 'login' );
		$this->command->check( array( '203.0.113.5' ), array() );
		self::assertSame( 'Not locked. 4 failed attempts left for 203.0.113.5.', $this->last( 'line' ) );

		$this->lock( '203.0.113.6', 'b' );
		$this->command->check( array( '203.0.113.6' ), array( 'user' => 'b' ) );
		self::assertSame( 'Locked (ip) for 900 more seconds, lockout number 1.', $this->last( 'line' ) );

		self::settings( array( 'allowlist' => array( '192.0.2.1' ), 'denylist' => array( '192.0.2.2' ) ) );
		$this->command->check( array( '192.0.2.1' ), array() );
		self::assertStringContainsString( 'allowlist', $this->last( 'line' ) );
		$this->command->check( array( '192.0.2.2' ), array() );
		self::assertStringContainsString( 'denylist', $this->last( 'line' ) );

		$this->expectException( WpCliHalt::class );
		$this->command->check( array( 'nope' ), array() );
	}
}
