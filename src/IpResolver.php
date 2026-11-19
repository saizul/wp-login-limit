<?php
/**
 * Client IP resolution behind trusted proxies.
 *
 * @package Saizul\LoginLimit
 */

namespace Saizul\LoginLimit;

defined( 'ABSPATH' ) || exit;

/**
 * Finds the real client address.
 *
 * `REMOTE_ADDR` is the only value nobody can forge. Proxy headers are read
 * only when `REMOTE_ADDR` is one of the trusted proxies; for
 * `X-Forwarded-For` the list is walked from the right and the first address
 * that is not a trusted proxy wins, so a client cannot prepend a fake address.
 */
final class IpResolver {

	const HEADER_XFF        = 'x-forwarded-for';
	const HEADER_CLOUDFLARE = 'cf-connecting-ip';
	const HEADER_REAL_IP    = 'x-real-ip';
	const HEADERS           = array( self::HEADER_XFF, self::HEADER_CLOUDFLARE, self::HEADER_REAL_IP );

	/**
	 * Cloudflare's published edge ranges (https://www.cloudflare.com/ips/).
	 * Check them from time to time; add new ranges as trusted proxies until
	 * the plugin is updated.
	 */
	const CLOUDFLARE_RANGES = array(
		'173.245.48.0/20',
		'103.21.244.0/22',
		'103.22.200.0/22',
		'103.31.4.0/22',
		'141.101.64.0/18',
		'108.162.192.0/18',
		'190.93.240.0/20',
		'188.114.96.0/20',
		'197.234.240.0/22',
		'198.41.128.0/17',
		'162.158.0.0/15',
		'104.16.0.0/13',
		'104.24.0.0/14',
		'172.64.0.0/13',
		'131.0.72.0/22',
		'2400:cb00::/32',
		'2606:4700::/32',
		'2803:f800::/32',
		'2405:b500::/32',
		'2405:8100::/32',
		'2a06:98c0::/29',
		'2c0f:f248::/32',
	);

	/**
	 * Trusted proxy ranges (normalised).
	 *
	 * @var string[]
	 */
	private $proxies;

	/**
	 * Header read from trusted proxies.
	 *
	 * @var string
	 */
	private $header;

	/**
	 * Whether Cloudflare ranges are trusted (CF-Connecting-IP for those).
	 *
	 * @var bool
	 */
	private $cloudflare;

	/**
	 * Constructor.
	 *
	 * @param string[] $proxies    Trusted proxy addresses or CIDR ranges.
	 * @param string   $header     One of HEADERS.
	 * @param bool     $cloudflare Trust Cloudflare's ranges with CF-Connecting-IP.
	 */
	public function __construct( array $proxies = array(), string $header = self::HEADER_XFF, bool $cloudflare = false ) {
		$this->proxies    = $proxies;
		$this->header     = in_array( $header, self::HEADERS, true ) ? $header : self::HEADER_XFF;
		$this->cloudflare = $cloudflare;
	}

	/**
	 * Build from the plugin settings.
	 *
	 * @param array<string,mixed> $settings Settings.
	 */
	public static function from_settings( array $settings ): self {
		return new self(
			(array) ( $settings['trusted_proxies'] ?? array() ),
			(string) ( $settings['proxy_header'] ?? self::HEADER_XFF ),
			! empty( $settings['trust_cloudflare'] )
		);
	}

	/**
	 * Client address for a request, normalised, or an empty string when even
	 * `REMOTE_ADDR` is missing or invalid.
	 *
	 * @param array<string,mixed> $server `$_SERVER`.
	 */
	public function resolve( array $server ): string {
		$remote = Ip::normalize( self::value( $server, 'REMOTE_ADDR' ) );
		if ( null === $remote ) {
			return '';
		}

		$from_cloudflare = $this->cloudflare && Ip::matches( $remote, self::CLOUDFLARE_RANGES );
		if ( ! $from_cloudflare && ! Ip::matches( $remote, $this->proxies ) ) {
			return $remote;
		}

		$header = $from_cloudflare ? self::HEADER_CLOUDFLARE : $this->header;
		if ( self::HEADER_XFF !== $header ) {
			$key   = self::HEADER_CLOUDFLARE === $header ? 'HTTP_CF_CONNECTING_IP' : 'HTTP_X_REAL_IP';
			$value = Ip::normalize( self::strip_port( self::value( $server, $key ) ) );
			if ( null !== $value ) {
				return $value;
			}
			// A Cloudflare edge without the header (or with a bad one): fall back to X-Forwarded-For.
			if ( ! $from_cloudflare ) {
				return $remote;
			}
		}

		return $this->walk_forwarded_for( self::value( $server, 'HTTP_X_FORWARDED_FOR' ), $remote );
	}

	/**
	 * Whether an address is a trusted proxy (configured or Cloudflare).
	 *
	 * @param string $ip Address.
	 */
	public function is_trusted_proxy( string $ip ): bool {
		return Ip::matches( $ip, $this->proxies ) || ( $this->cloudflare && Ip::matches( $ip, self::CLOUDFLARE_RANGES ) );
	}

	/**
	 * Walk X-Forwarded-For from the right, skipping trusted proxies.
	 *
	 * @param string $header Header value.
	 * @param string $remote REMOTE_ADDR (a trusted proxy).
	 */
	private function walk_forwarded_for( string $header, string $remote ): string {
		$client = $remote;
		$hops   = array_reverse( array_map( 'trim', explode( ',', $header ) ) );
		foreach ( array_slice( $hops, 0, 20 ) as $hop ) {
			if ( '' === $hop ) {
				continue;
			}
			$ip = Ip::normalize( self::strip_port( $hop ) );
			if ( null === $ip ) {
				// Garbage in the chain: trust nothing further to the left.
				return $client;
			}
			$client = $ip;
			if ( ! $this->is_trusted_proxy( $ip ) ) {
				return $ip;
			}
		}

		return $client;
	}

	/**
	 * Remove a port: `192.0.2.1:8080` and `[2001:db8::1]:443`.
	 *
	 * @param string $value Address, maybe with a port.
	 */
	private static function strip_port( string $value ): string {
		$value = trim( $value );
		if ( preg_match( '/^\[([0-9a-fA-F:.]+)\](?::\d+)?$/', $value, $m ) ) {
			return $m[1];
		}
		if ( preg_match( '/^(\d{1,3}(?:\.\d{1,3}){3}):\d+$/', $value, $m ) ) {
			return $m[1];
		}

		return $value;
	}

	/**
	 * String value from the server array.
	 *
	 * @param array<string,mixed> $server Server array.
	 * @param string              $key    Key.
	 */
	private static function value( array $server, string $key ): string {
		if ( ! isset( $server[ $key ] ) || ! is_string( $server[ $key ] ) ) {
			return '';
		}

		// Keep the right end: that is where the trusted proxies append addresses.
		return strlen( $server[ $key ] ) > 8192 ? substr( $server[ $key ], -8192 ) : $server[ $key ];
	}
}
