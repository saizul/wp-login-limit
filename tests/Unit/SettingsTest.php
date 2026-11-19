<?php
declare(strict_types=1);

namespace Saizul\LoginLimit\Tests\Unit;

use Saizul\LoginLimit\IpResolver;
use Saizul\LoginLimit\Settings;
use Saizul\LoginLimit\Tests\WpTestCase;
use WpStubs;

/**
 * Settings defaults and sanitising.
 */
final class SettingsTest extends WpTestCase {

	public function test_defaults_and_merge(): void {
		WpStubs::$options[ Settings::OPTION ] = array( 'ip_max_retries' => 3 );
		$settings                            = Settings::get();

		self::assertSame( 3, $settings['ip_max_retries'] );
		self::assertSame( 10, $settings['user_max_retries'] );
		self::assertSame( Settings::XMLRPC_LIMIT, $settings['xmlrpc'] );
		self::assertTrue( $settings['generic_errors'] );
		self::assertFalse( $settings['fail2ban'] );

		WpStubs::$options[ Settings::OPTION ] = 'corrupt';
		self::assertSame( Settings::defaults(), Settings::get() );
	}

	public function test_numbers_are_clamped(): void {
		$out = Settings::sanitize(
			array(
				'ip_max_retries'     => '0',
				'user_max_retries'   => '-5',
				'window'             => '5',
				'lockout_duration'   => '120',
				'lockout_multiplier' => '99',
				'lockout_max'        => '60',
				'lockout_memory'     => 'abc',
				'ipv6_prefix'        => '200',
				'notify_interval'    => '1',
				'log_retention_days' => '9999',
			)
		);

		self::assertSame( 1, $out['ip_max_retries'] );
		self::assertSame( 0, $out['user_max_retries'] );
		self::assertSame( 60, $out['window'] );
		self::assertSame( 120, $out['lockout_duration'] );
		self::assertSame( 10, $out['lockout_multiplier'] );
		self::assertSame( 120, $out['lockout_max'] );
		self::assertSame( 3600, $out['lockout_memory'] );
		self::assertSame( 128, $out['ipv6_prefix'] );
		self::assertSame( 300, $out['notify_interval'] );
		self::assertSame( 3650, $out['log_retention_days'] );
	}

	public function test_ip_lists_keep_valid_unique_entries(): void {
		$out = Settings::sanitize(
			array(
				'allowlist'       => "203.0.113.7\n198.51.100.77/24 # office\n\nnot-an-ip\n203.0.113.7\n2001:DB8::/32",
				'denylist'        => array( '10.0.0.0/8', array( 'x' ), '999.1.1.1' ),
				'trusted_proxies' => '10.0.0.1, 10.0.0.2',
			)
		);

		self::assertSame( array( '203.0.113.7', '198.51.100.0/24', '2001:db8::/32' ), $out['allowlist'] );
		self::assertSame( array( '10.0.0.0/8' ), $out['denylist'] );
		self::assertSame( array( '10.0.0.1', '10.0.0.2' ), $out['trusted_proxies'] );
	}

	public function test_ip_list_is_capped(): void {
		$lines = array();
		for ( $i = 0; $i < 700; $i++ ) {
			$lines[] = '10.0.' . intdiv( $i, 256 ) . '.' . ( $i % 256 );
		}
		self::assertCount( Settings::MAX_LIST, Settings::ip_list( implode( "\n", $lines ) ) );
	}

	public function test_choices_and_booleans(): void {
		$out = Settings::sanitize(
			array(
				'proxy_header'     => IpResolver::HEADER_CLOUDFLARE,
				'trust_cloudflare' => '1',
				'xmlrpc'           => 'disable',
				'notify'           => 'all',
				'generic_errors'   => '',
				'fail2ban'         => 'on',
			)
		);

		self::assertSame( IpResolver::HEADER_CLOUDFLARE, $out['proxy_header'] );
		self::assertTrue( $out['trust_cloudflare'] );
		self::assertSame( Settings::XMLRPC_DISABLE, $out['xmlrpc'] );
		self::assertSame( Settings::NOTIFY_ALL, $out['notify'] );
		self::assertFalse( $out['generic_errors'] );
		self::assertTrue( $out['fail2ban'] );

		$bad = Settings::sanitize( array( 'proxy_header' => 'x-evil', 'xmlrpc' => 'off', 'notify' => 'spam' ) );
		self::assertSame( IpResolver::HEADER_XFF, $bad['proxy_header'] );
		self::assertSame( Settings::XMLRPC_LIMIT, $bad['xmlrpc'] );
		self::assertSame( Settings::NOTIFY_ESCALATED, $bad['notify'] );
	}

	public function test_email_and_usernames(): void {
		$out = Settings::sanitize(
			array(
				'notify_email'   => ' security@example.org ',
				'deny_usernames' => "Admin\nadmin\n test \n\n",
			)
		);
		self::assertSame( 'security@example.org', $out['notify_email'] );
		self::assertSame( array( 'admin', 'test' ), $out['deny_usernames'] );

		self::assertSame( '', Settings::sanitize( array( 'notify_email' => 'not an email' ) )['notify_email'] );
		self::assertSame( '', Settings::sanitize( array( 'notify_email' => array( 'a@b.c' ) ) )['notify_email'] );
	}

	public function test_non_array_input(): void {
		self::assertSame( 5, Settings::sanitize( null )['ip_max_retries'] );
	}
}
