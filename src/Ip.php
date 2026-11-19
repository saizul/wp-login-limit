<?php
/**
 * IP address and CIDR helpers.
 *
 * @package Saizul\LoginLimit
 */

namespace Saizul\LoginLimit;

defined( 'ABSPATH' ) || exit;

/**
 * Validates, normalises and matches IPv4 and IPv6 addresses and CIDR ranges.
 * Pure functions, no WordPress calls.
 */
final class Ip {

	/**
	 * Normalised address, or null when invalid. IPv4-mapped IPv6 addresses
	 * (`::ffff:192.0.2.1`) become plain IPv4.
	 *
	 * @param string $ip Address.
	 */
	public static function normalize( string $ip ): ?string {
		$packed = self::pack( trim( $ip ) );

		return null === $packed ? null : (string) inet_ntop( $packed );
	}

	/**
	 * Whether the string is a valid IPv4 or IPv6 address.
	 *
	 * @param string $ip Address.
	 */
	public static function is_valid( string $ip ): bool {
		return null !== self::pack( trim( $ip ) );
	}

	/**
	 * Whether the address is IPv6 (after unmapping IPv4-mapped addresses).
	 *
	 * @param string $ip Address.
	 */
	public static function is_v6( string $ip ): bool {
		$packed = self::pack( $ip );

		return null !== $packed && 16 === strlen( $packed );
	}

	/**
	 * Normalise one list entry: a single address or a CIDR range.
	 *
	 * @param string $entry Raw entry, for example `203.0.113.7`, `198.51.100.0/24` or `2001:db8::/32`.
	 * @return string|null Normalised entry (host bits cleared), or null when invalid.
	 */
	public static function normalize_entry( string $entry ): ?string {
		$entry = trim( $entry );
		if ( '' === $entry ) {
			return null;
		}

		$bits = null;
		if ( false !== strpos( $entry, '/' ) ) {
			list( $entry, $bits ) = explode( '/', $entry, 2 );
			if ( ! ctype_digit( $bits ) ) {
				return null;
			}
			$bits = (int) $bits;
		}

		$packed = self::pack( $entry );
		if ( null === $packed ) {
			return null;
		}
		$max = strlen( $packed ) * 8;
		if ( null === $bits ) {
			return (string) inet_ntop( $packed );
		}
		if ( $bits > $max ) {
			return null;
		}

		return inet_ntop( self::mask( $packed, $bits ) ) . '/' . $bits;
	}

	/**
	 * Whether an address is inside one of the entries.
	 *
	 * @param string   $ip      Address.
	 * @param string[] $entries Addresses or CIDR ranges.
	 */
	public static function matches( string $ip, array $entries ): bool {
		$packed = self::pack( $ip );
		if ( null === $packed ) {
			return false;
		}
		foreach ( $entries as $entry ) {
			if ( ! is_string( $entry ) || '' === $entry ) {
				continue;
			}
			$bits = null;
			$base = $entry;
			if ( false !== strpos( $entry, '/' ) ) {
				list( $base, $bits ) = explode( '/', $entry, 2 );
				$bits                = (int) $bits;
			}
			$range = self::pack( $base );
			if ( null === $range || strlen( $range ) !== strlen( $packed ) ) {
				continue;
			}
			if ( null === $bits ) {
				$bits = strlen( $packed ) * 8;
			}
			if ( self::mask( $packed, $bits ) === self::mask( $range, $bits ) ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Key used for counting: the address itself for IPv4, the network of
	 * `$v6_prefix` bits for IPv6 (one customer usually gets a whole /64).
	 *
	 * @param string $ip        Address.
	 * @param int    $v6_prefix IPv6 prefix length, 1 to 128.
	 */
	public static function network( string $ip, int $v6_prefix = 64 ): string {
		$packed = self::pack( $ip );
		if ( null === $packed ) {
			return '';
		}
		if ( 4 === strlen( $packed ) ) {
			return (string) inet_ntop( $packed );
		}
		$v6_prefix = max( 1, min( 128, $v6_prefix ) );
		if ( 128 === $v6_prefix ) {
			return (string) inet_ntop( $packed );
		}

		return inet_ntop( self::mask( $packed, $v6_prefix ) ) . '/' . $v6_prefix;
	}

	/**
	 * Whether an address is private, loopback or reserved (not a public address).
	 *
	 * @param string $ip Address.
	 */
	public static function is_private( string $ip ): bool {
		$ip = (string) self::normalize( $ip );

		return '' !== $ip && false === filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE );
	}

	/**
	 * Binary form of an address, or null. IPv4-mapped IPv6 becomes 4 bytes.
	 *
	 * @param string $ip Address.
	 */
	private static function pack( string $ip ): ?string {
		if ( false === filter_var( $ip, FILTER_VALIDATE_IP ) ) {
			return null;
		}
		$packed = inet_pton( $ip );
		if ( false === $packed ) {
			return null;
		}
		if ( 16 === strlen( $packed ) && 0 === strncmp( $packed, str_repeat( "\0", 10 ) . "\xff\xff", 12 ) ) {
			return substr( $packed, 12 );
		}

		return $packed;
	}

	/**
	 * Keep the first `$bits` bits of a binary address, zero the rest.
	 *
	 * @param string $packed Binary address.
	 * @param int    $bits   Prefix length.
	 */
	private static function mask( string $packed, int $bits ): string {
		$out    = '';
		$length = strlen( $packed );
		for ( $i = 0; $i < $length; $i++ ) {
			$keep = max( 0, min( 8, $bits - ( $i * 8 ) ) );
			$byte = 0 === $keep ? 0 : ( 0xFF << ( 8 - $keep ) ) & 0xFF;
			$out .= chr( ord( $packed[ $i ] ) & $byte );
		}

		return $out;
	}
}
