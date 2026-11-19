<?php
declare(strict_types=1);

namespace Saizul\LoginLimit\Tests\Unit;

use PHPUnit\Framework\TestCase;
use Saizul\LoginLimit\Ip;

/**
 * Addresses, CIDR ranges and IPv6 networks.
 */
final class IpTest extends TestCase {

	/**
	 * @return array<string,array{0:string,1:?string}>
	 */
	public static function entries(): array {
		return array(
			'ipv4'                    => array( '203.0.113.7', '203.0.113.7' ),
			'ipv4 with spaces'        => array( '  203.0.113.7 ', '203.0.113.7' ),
			'ipv4 cidr'               => array( '198.51.100.0/24', '198.51.100.0/24' ),
			'ipv4 cidr host bits'     => array( '198.51.100.77/24', '198.51.100.0/24' ),
			'ipv4 /0'                 => array( '10.1.2.3/0', '0.0.0.0/0' ),
			'ipv4 /32'                => array( '10.1.2.3/32', '10.1.2.3/32' ),
			'ipv4 /33'                => array( '10.1.2.3/33', null ),
			'ipv6'                    => array( '2001:DB8:0:0::1', '2001:db8::1' ),
			'ipv6 cidr'               => array( '2001:db8:abcd:12::/48', '2001:db8:abcd::/48' ),
			'ipv6 /128'               => array( '::1/128', '::1/128' ),
			'ipv6 /129'               => array( '::1/129', null ),
			'mapped ipv4'             => array( '::ffff:192.0.2.1', '192.0.2.1' ),
			'garbage'                 => array( 'not-an-ip', null ),
			'negative bits'           => array( '10.0.0.0/-1', null ),
			'letters in bits'         => array( '10.0.0.0/8a', null ),
			'empty'                   => array( '', null ),
			'octet out of range'      => array( '256.1.1.1', null ),
			'leading zeros (invalid)' => array( '010.1.1.1', null ),
		);
	}

	/**
	 * @dataProvider entries
	 */
	public function test_normalize_entry( string $entry, ?string $expected ): void {
		self::assertSame( $expected, Ip::normalize_entry( $entry ) );
	}

	/**
	 * @return array<string,array{0:string,1:string[],2:bool}>
	 */
	public static function match_cases(): array {
		return array(
			'exact ipv4'               => array( '203.0.113.7', array( '203.0.113.7' ), true ),
			'other ipv4'               => array( '203.0.113.8', array( '203.0.113.7' ), false ),
			'in /24'                   => array( '198.51.100.250', array( '198.51.100.0/24' ), true ),
			'outside /24'              => array( '198.51.101.1', array( '198.51.100.0/24' ), false ),
			'/20 boundary low'         => array( '173.245.48.0', array( '173.245.48.0/20' ), true ),
			'/20 boundary high'        => array( '173.245.63.255', array( '173.245.48.0/20' ), true ),
			'/20 just outside'         => array( '173.245.64.0', array( '173.245.48.0/20' ), false ),
			'/0 matches all v4'        => array( '8.8.8.8', array( '0.0.0.0/0' ), true ),
			'/0 v4 does not match v6'  => array( '2001:db8::1', array( '0.0.0.0/0' ), false ),
			'ipv6 in /32'              => array( '2001:db8:ffff::1', array( '2001:db8::/32' ), true ),
			'ipv6 outside /32'         => array( '2001:db9::1', array( '2001:db8::/32' ), false ),
			'ipv6 /29 range'           => array( '2a06:98c7:1::1', array( '2a06:98c0::/29' ), true ),
			'ipv6 just outside /29'    => array( '2a06:98c8::1', array( '2a06:98c0::/29' ), false ),
			'mapped v4 in v4 range'    => array( '::ffff:198.51.100.5', array( '198.51.100.0/24' ), true ),
			'invalid ip'               => array( 'x', array( '0.0.0.0/0' ), false ),
			'skips junk entries'       => array( '10.0.0.1', array( '', 'junk', '10.0.0.0/8' ), true ),
			'empty list'               => array( '10.0.0.1', array(), false ),
		);
	}

	/**
	 * @dataProvider match_cases
	 * @param string[] $entries Entries.
	 */
	public function test_matches( string $ip, array $entries, bool $expected ): void {
		self::assertSame( $expected, Ip::matches( $ip, $entries ) );
	}

	public function test_network_groups_ipv6_by_prefix(): void {
		self::assertSame( '203.0.113.7', Ip::network( '203.0.113.7' ) );
		self::assertSame( '2001:db8:1:2::/64', Ip::network( '2001:db8:1:2:aaaa:bbbb:cccc:dddd' ) );
		self::assertSame( Ip::network( '2001:db8:1:2::1' ), Ip::network( '2001:db8:1:2:ffff::9' ) );
		self::assertSame( '2001:db8:1::/48', Ip::network( '2001:db8:1:2::1', 48 ) );
		self::assertSame( '2001:db8:1:2::1', Ip::network( '2001:db8:1:2::1', 128 ) );
		self::assertSame( '192.0.2.1', Ip::network( '::ffff:192.0.2.1' ) );
		self::assertSame( '', Ip::network( 'nope' ) );
	}

	public function test_helpers(): void {
		self::assertSame( '2001:db8::1', Ip::normalize( ' 2001:0DB8::0001 ' ) );
		self::assertNull( Ip::normalize( '1.2.3' ) );
		self::assertTrue( Ip::is_valid( '::1' ) );
		self::assertFalse( Ip::is_valid( '' ) );
		self::assertTrue( Ip::is_v6( '2001:db8::1' ) );
		self::assertFalse( Ip::is_v6( '::ffff:192.0.2.1' ) );
		self::assertTrue( Ip::is_private( '10.0.0.5' ) );
		self::assertTrue( Ip::is_private( '127.0.0.1' ) );
		self::assertTrue( Ip::is_private( 'fd00::1' ) );
		self::assertFalse( Ip::is_private( '8.8.8.8' ) );
		self::assertFalse( Ip::is_private( 'nope' ) );
	}
}
