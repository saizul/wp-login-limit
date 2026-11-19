<?php
declare(strict_types=1);

namespace Saizul\LoginLimit\Tests\Unit;

use Saizul\LoginLimit\Fail2ban;
use Saizul\LoginLimit\Lockout;
use Saizul\LoginLimit\Notifier;
use Saizul\LoginLimit\Settings;
use Saizul\LoginLimit\Tests\WpTestCase;
use WpStubs;

/**
 * Throttled admin email and fail2ban lines.
 */
final class NotifierTest extends WpTestCase {

	private static function lockout( int $level, string $reason = Lockout::REASON_IP ): Lockout {
		return new Lockout( $reason, self::NOW + 900, 900, $level, '203.0.113.5', 'admin', 'xmlrpc' );
	}

	/**
	 * @param array<string,mixed> $settings Settings.
	 */
	private static function notifier( array $settings ): Notifier {
		return new Notifier( array_merge( Settings::defaults(), $settings ) );
	}

	public function test_none_never_sends(): void {
		self::assertFalse( self::notifier( array( 'notify' => Settings::NOTIFY_NONE ) )->lockout( self::lockout( 5 ), self::NOW ) );
		self::assertSame( array(), WpStubs::$mail );
	}

	public function test_escalated_sends_from_the_second_lockout(): void {
		$notifier = self::notifier( array( 'notify' => Settings::NOTIFY_ESCALATED ) );

		self::assertFalse( $notifier->lockout( self::lockout( 1 ), self::NOW ) );
		self::assertTrue( $notifier->lockout( self::lockout( 2 ), self::NOW ) );
		self::assertSame( '[Example & Co] Login lockout: 203.0.113.5', WpStubs::$mail[0]['subject'] );
		self::assertStringContainsString( 'IP address: 203.0.113.5', WpStubs::$mail[0]['message'] );
		self::assertStringContainsString( 'Via: xmlrpc', WpStubs::$mail[0]['message'] );
		self::assertStringContainsString( 'Duration: 15 minutes', WpStubs::$mail[0]['message'] );
		self::assertStringContainsString( 'options-general.php?page=wp-login-limit', WpStubs::$mail[0]['message'] );
	}

	public function test_throttle_counts_suppressed_lockouts(): void {
		$notifier = self::notifier( array( 'notify' => Settings::NOTIFY_ALL, 'notify_interval' => 3600, 'notify_email' => 'sec@example.org' ) );

		self::assertTrue( $notifier->lockout( self::lockout( 1 ), self::NOW ) );
		self::assertFalse( $notifier->lockout( self::lockout( 1 ), self::NOW + 10 ) );
		self::assertFalse( $notifier->lockout( self::lockout( 1, Lockout::REASON_USER ), self::NOW + 3599 ) );
		self::assertCount( 1, WpStubs::$mail );
		self::assertSame( 2, WpStubs::$options[ Notifier::STATE_OPTION ]['pending'] );

		self::assertTrue( $notifier->lockout( self::lockout( 1, Lockout::REASON_USER ), self::NOW + 3600 ) );
		self::assertCount( 2, WpStubs::$mail );
		self::assertSame( 'sec@example.org', WpStubs::$mail[1]['to'] );
		self::assertSame( '[Example & Co] Login lockout: admin', WpStubs::$mail[1]['subject'] );
		self::assertStringContainsString( '2 more lockouts happened since the last email.', WpStubs::$mail[1]['message'] );
		self::assertSame( 0, WpStubs::$options[ Notifier::STATE_OPTION ]['pending'] );
	}

	public function test_filter_can_stop_the_email(): void {
		add_filter( 'login_limit_send_notification', '__return_false' );

		self::assertFalse( self::notifier( array( 'notify' => Settings::NOTIFY_ALL ) )->lockout( self::lockout( 1 ), self::NOW ) );
		self::assertSame( array(), WpStubs::$mail );
	}

	public function test_no_recipient(): void {
		unset( WpStubs::$options['admin_email'] );

		self::assertFalse( self::notifier( array( 'notify' => Settings::NOTIFY_ALL ) )->lockout( self::lockout( 1 ), self::NOW ) );
	}

	/**
	 * @return array<string,array{0:string,1:string,2:string,3:string,4:string}>
	 */
	public static function lines(): array {
		return array(
			'failure'         => array( 'authentication failure', '203.0.113.5', 'admin', 'login', 'wp-login-limit: authentication failure from 203.0.113.5 user="admin" gateway=login' ),
			'ipv6'            => array( 'lockout', '2001:DB8::1', 'a.b@c.d', 'xmlrpc', 'wp-login-limit: lockout from 2001:db8::1 user="a.b@c.d" gateway=xmlrpc' ),
			'injection'       => array( 'blocked', '203.0.113.5', "x\" from 6.6.6.6\nwp-login-limit: lockout", 'rest', 'wp-login-limit: blocked from 203.0.113.5 user="x??from?6.6.6.6?wp-login-limit??lockout" gateway=rest' ),
			'unknown ip'      => array( 'lockout', 'nope', '', '', 'wp-login-limit: lockout from unknown user="" gateway=login' ),
			'gateway cleaned' => array( 'lockout', '203.0.113.5', 'u', 'X ML;RPC', 'wp-login-limit: lockout from 203.0.113.5 user="u" gateway=xmlrpc' ),
		);
	}

	/**
	 * @dataProvider lines
	 */
	public function test_fail2ban_line( string $event, string $ip, string $username, string $gateway, string $expected ): void {
		self::assertSame( $expected, Fail2ban::line( $event, $ip, $username, $gateway ) );
	}

	public function test_fail2ban_unknown_event_and_length(): void {
		self::assertSame( '', Fail2ban::line( 'other', '203.0.113.5', 'u', 'login' ) );
		self::assertStringContainsString( 'user="' . str_repeat( 'a', 60 ) . '"', Fail2ban::line( 'lockout', '203.0.113.5', str_repeat( 'a', 200 ), 'login' ) );
	}

	public function test_fail2ban_line_matches_the_example_filter(): void {
		$conf = (string) file_get_contents( dirname( __DIR__, 2 ) . '/examples/fail2ban/filter.d/wp-login-limit.conf' );
		self::assertSame( 1, preg_match( '/^failregex\s*=\s*(.+)$/m', $conf, $m ) );
		$regex = '/' . str_replace( array( '<HOST>', '/' ), array( '(?P<host>\S+)', '\/' ), trim( $m[1] ) ) . '/';

		$line = '[19-Nov-2026 10:00:00 UTC] ' . Fail2ban::line( 'authentication failure', '203.0.113.5', 'admin', 'login' );
		self::assertSame( 1, preg_match( $regex, $line, $host ) );
		self::assertSame( '203.0.113.5', $host['host'] );

		$forged = '[19-Nov-2026 10:00:00 UTC] ' . Fail2ban::line( 'authentication failure', '203.0.113.5', 'x from 6.6.6.6', 'login' );
		self::assertSame( 1, preg_match( $regex, $forged, $host ) );
		self::assertSame( '203.0.113.5', $host['host'] );
	}
}
