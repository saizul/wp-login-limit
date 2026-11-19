<?php
declare(strict_types=1);

namespace Saizul\LoginLimit\Tests\Unit;

use PHPUnit\Framework\TestCase;
use Saizul\LoginLimit\IpResolver;

/**
 * Real client IP behind trusted proxies.
 */
final class IpResolverTest extends TestCase {

	public function test_remote_addr_without_trusted_proxies_ignores_headers(): void {
		$resolver = new IpResolver();

		self::assertSame(
			'203.0.113.5',
			$resolver->resolve(
				array(
					'REMOTE_ADDR'           => '203.0.113.5',
					'HTTP_X_FORWARDED_FOR'  => '1.1.1.1',
					'HTTP_CF_CONNECTING_IP' => '2.2.2.2',
					'HTTP_X_REAL_IP'        => '3.3.3.3',
				)
			)
		);
	}

	public function test_headers_from_untrusted_remote_are_ignored(): void {
		$resolver = new IpResolver( array( '10.0.0.0/8' ) );

		self::assertSame( '198.51.100.9', $resolver->resolve( array( 'REMOTE_ADDR' => '198.51.100.9', 'HTTP_X_FORWARDED_FOR' => '1.1.1.1' ) ) );
	}

	public function test_forwarded_for_from_trusted_proxy(): void {
		$resolver = new IpResolver( array( '10.0.0.0/8' ) );

		self::assertSame( '203.0.113.5', $resolver->resolve( array( 'REMOTE_ADDR' => '10.0.0.2', 'HTTP_X_FORWARDED_FOR' => '203.0.113.5' ) ) );
	}

	public function test_spoofed_left_entries_are_ignored(): void {
		$resolver = new IpResolver( array( '10.0.0.0/8' ) );

		// The client sent "X-Forwarded-For: 1.1.1.1"; the proxy appended the real address.
		self::assertSame( '203.0.113.5', $resolver->resolve( array( 'REMOTE_ADDR' => '10.0.0.2', 'HTTP_X_FORWARDED_FOR' => '1.1.1.1, 203.0.113.5' ) ) );
	}

	public function test_chain_of_trusted_proxies_is_skipped(): void {
		$resolver = new IpResolver( array( '10.0.0.0/8', '192.0.2.10' ) );

		self::assertSame( '203.0.113.5', $resolver->resolve( array( 'REMOTE_ADDR' => '10.0.0.2', 'HTTP_X_FORWARDED_FOR' => '1.1.1.1,203.0.113.5, 192.0.2.10 ,10.9.9.9' ) ) );
	}

	public function test_all_trusted_returns_the_leftmost(): void {
		$resolver = new IpResolver( array( '10.0.0.0/8' ) );

		self::assertSame( '10.1.1.1', $resolver->resolve( array( 'REMOTE_ADDR' => '10.0.0.2', 'HTTP_X_FORWARDED_FOR' => '10.1.1.1, 10.2.2.2' ) ) );
	}

	public function test_garbage_stops_the_walk(): void {
		$resolver = new IpResolver( array( '10.0.0.0/8' ) );

		self::assertSame( '10.2.2.2', $resolver->resolve( array( 'REMOTE_ADDR' => '10.0.0.2', 'HTTP_X_FORWARDED_FOR' => '1.1.1.1, <script>, 10.2.2.2' ) ) );
		self::assertSame( '10.0.0.2', $resolver->resolve( array( 'REMOTE_ADDR' => '10.0.0.2', 'HTTP_X_FORWARDED_FOR' => 'unknown' ) ) );
		self::assertSame( '10.0.0.2', $resolver->resolve( array( 'REMOTE_ADDR' => '10.0.0.2' ) ) );
	}

	public function test_ports_and_brackets_are_stripped(): void {
		$resolver = new IpResolver( array( '10.0.0.0/8' ) );

		self::assertSame( '203.0.113.5', $resolver->resolve( array( 'REMOTE_ADDR' => '10.0.0.2', 'HTTP_X_FORWARDED_FOR' => '203.0.113.5:52100' ) ) );
		self::assertSame( '2001:db8::5', $resolver->resolve( array( 'REMOTE_ADDR' => '10.0.0.2', 'HTTP_X_FORWARDED_FOR' => '[2001:db8::5]:443' ) ) );
	}

	public function test_x_real_ip_header(): void {
		$resolver = new IpResolver( array( '127.0.0.1' ), IpResolver::HEADER_REAL_IP );

		self::assertSame( '203.0.113.5', $resolver->resolve( array( 'REMOTE_ADDR' => '127.0.0.1', 'HTTP_X_REAL_IP' => '203.0.113.5', 'HTTP_X_FORWARDED_FOR' => '1.1.1.1' ) ) );
		self::assertSame( '127.0.0.1', $resolver->resolve( array( 'REMOTE_ADDR' => '127.0.0.1', 'HTTP_X_REAL_IP' => 'bogus' ) ) );
	}

	public function test_cloudflare_ranges(): void {
		$resolver = new IpResolver( array(), IpResolver::HEADER_XFF, true );

		self::assertSame( '203.0.113.5', $resolver->resolve( array( 'REMOTE_ADDR' => '173.245.48.10', 'HTTP_CF_CONNECTING_IP' => '203.0.113.5' ) ) );
		self::assertSame( '2001:db8::77', $resolver->resolve( array( 'REMOTE_ADDR' => '2606:4700::1', 'HTTP_CF_CONNECTING_IP' => '2001:db8::77' ) ) );
		// Not from Cloudflare: the header is a forgery.
		self::assertSame( '198.51.100.1', $resolver->resolve( array( 'REMOTE_ADDR' => '198.51.100.1', 'HTTP_CF_CONNECTING_IP' => '203.0.113.5' ) ) );
		// From Cloudflare without the header: fall back to X-Forwarded-For.
		self::assertSame( '203.0.113.9', $resolver->resolve( array( 'REMOTE_ADDR' => '173.245.48.10', 'HTTP_X_FORWARDED_FOR' => '203.0.113.9' ) ) );
		self::assertTrue( $resolver->is_trusted_proxy( '104.16.0.1' ) );
		self::assertFalse( ( new IpResolver() )->is_trusted_proxy( '104.16.0.1' ) );
	}

	public function test_cloudflare_behind_own_load_balancer(): void {
		// Load balancer 10.0.0.2 -> Cloudflare edge -> client.
		$resolver = new IpResolver( array( '10.0.0.0/8' ), IpResolver::HEADER_XFF, true );

		self::assertSame( '203.0.113.5', $resolver->resolve( array( 'REMOTE_ADDR' => '10.0.0.2', 'HTTP_X_FORWARDED_FOR' => '6.6.6.6, 203.0.113.5, 172.64.0.9' ) ) );
	}

	public function test_invalid_remote_addr(): void {
		self::assertSame( '', ( new IpResolver() )->resolve( array() ) );
		self::assertSame( '', ( new IpResolver() )->resolve( array( 'REMOTE_ADDR' => 'localhost' ) ) );
		self::assertSame( '', ( new IpResolver() )->resolve( array( 'REMOTE_ADDR' => array( '1.2.3.4' ) ) ) );
	}

	public function test_mapped_and_unusual_forms_are_normalised(): void {
		self::assertSame( '192.0.2.1', ( new IpResolver() )->resolve( array( 'REMOTE_ADDR' => '::ffff:192.0.2.1' ) ) );
		self::assertSame( '2001:db8::1', ( new IpResolver() )->resolve( array( 'REMOTE_ADDR' => '2001:0db8:0000::1' ) ) );
	}

	public function test_from_settings_and_unknown_header(): void {
		$resolver = IpResolver::from_settings(
			array(
				'trusted_proxies'  => array( '10.0.0.0/8' ),
				'proxy_header'     => 'x-made-up',
				'trust_cloudflare' => false,
			)
		);

		self::assertSame( '203.0.113.5', $resolver->resolve( array( 'REMOTE_ADDR' => '10.0.0.2', 'HTTP_X_FORWARDED_FOR' => '203.0.113.5' ) ) );
	}

	public function test_very_long_header_is_bounded(): void {
		$resolver = new IpResolver( array( '10.0.0.0/8' ) );
		$header   = implode( ',', array_fill( 0, 2000, '10.1.1.1' ) ) . ', 203.0.113.5';

		self::assertSame( '203.0.113.5', $resolver->resolve( array( 'REMOTE_ADDR' => '10.0.0.2', 'HTTP_X_FORWARDED_FOR' => $header ) ) );
		// Only the last 20 hops are walked.
		self::assertSame( '10.1.1.1', $resolver->resolve( array( 'REMOTE_ADDR' => '10.0.0.2', 'HTTP_X_FORWARDED_FOR' => '203.0.113.5,' . implode( ',', array_fill( 0, 30, '10.1.1.1' ) ) ) ) );
	}
}
