<?php
/**
 * Plugin settings (one option).
 *
 * @package Saizul\LoginLimit
 */

namespace Saizul\LoginLimit;

defined( 'ABSPATH' ) || exit;

/**
 * Defaults, reading and sanitising of `wp_login_limit_settings`.
 */
final class Settings {

	const OPTION = 'wp_login_limit_settings';

	const XMLRPC_LIMIT   = 'limit';
	const XMLRPC_DISABLE = 'disable';

	const NOTIFY_NONE      = 'none';
	const NOTIFY_ESCALATED = 'escalated';
	const NOTIFY_ALL       = 'all';

	const MAX_LIST = 500;

	/**
	 * Default settings.
	 *
	 * @return array<string,mixed>
	 */
	public static function defaults(): array {
		return array(
			'ip_max_retries'     => 5,
			'user_max_retries'   => 10,
			'window'             => 900,
			'lockout_duration'   => 900,
			'lockout_multiplier' => 4,
			'lockout_max'        => 86400,
			'lockout_memory'     => 86400,
			'ipv6_prefix'        => 64,
			'trusted_proxies'    => array(),
			'proxy_header'       => IpResolver::HEADER_XFF,
			'trust_cloudflare'   => false,
			'allowlist'          => array(),
			'denylist'           => array(),
			'deny_usernames'     => array(),
			'xmlrpc'             => self::XMLRPC_LIMIT,
			'generic_errors'     => true,
			'notify'             => self::NOTIFY_ESCALATED,
			'notify_email'       => '',
			'notify_interval'    => 3600,
			'fail2ban'           => false,
			'log_retention_days' => 30,
		);
	}

	/**
	 * Current settings merged with the defaults.
	 *
	 * @return array<string,mixed>
	 */
	public static function get(): array {
		$stored = get_option( self::OPTION, array() );

		return array_merge( self::defaults(), is_array( $stored ) ? $stored : array() );
	}

	/**
	 * Sanitise settings input (Settings API callback, WP-CLI).
	 *
	 * @param mixed $input Raw input.
	 * @return array<string,mixed>
	 */
	public static function sanitize( $input ): array {
		$input = is_array( $input ) ? $input : array();
		$d     = self::defaults();
		$out   = array();

		$out['ip_max_retries']     = self::int_between( $input['ip_max_retries'] ?? $d['ip_max_retries'], 1, 100 );
		$out['user_max_retries']   = self::int_between( $input['user_max_retries'] ?? $d['user_max_retries'], 0, 1000 );
		$out['window']             = self::int_between( $input['window'] ?? $d['window'], 60, 86400 );
		$out['lockout_duration']   = self::int_between( $input['lockout_duration'] ?? $d['lockout_duration'], 60, 604800 );
		$out['lockout_multiplier'] = self::int_between( $input['lockout_multiplier'] ?? $d['lockout_multiplier'], 1, 10 );
		$out['lockout_max']        = self::int_between( $input['lockout_max'] ?? $d['lockout_max'], $out['lockout_duration'], 2592000 );
		$out['lockout_memory']     = self::int_between( $input['lockout_memory'] ?? $d['lockout_memory'], 3600, 2592000 );
		$out['ipv6_prefix']        = self::int_between( $input['ipv6_prefix'] ?? $d['ipv6_prefix'], 32, 128 );

		$out['trusted_proxies']  = self::ip_list( $input['trusted_proxies'] ?? array() );
		$out['allowlist']        = self::ip_list( $input['allowlist'] ?? array() );
		$out['denylist']         = self::ip_list( $input['denylist'] ?? array() );
		$out['proxy_header']     = in_array( $input['proxy_header'] ?? '', IpResolver::HEADERS, true ) ? (string) $input['proxy_header'] : $d['proxy_header'];
		$out['trust_cloudflare'] = ! empty( $input['trust_cloudflare'] );

		$usernames = array();
		foreach ( self::lines( $input['deny_usernames'] ?? array() ) as $name ) {
			$name = Limiter::normalize_username( $name );
			if ( '' !== $name ) {
				$usernames[] = $name;
			}
		}
		$out['deny_usernames'] = array_slice( array_values( array_unique( $usernames ) ), 0, 100 );

		$out['xmlrpc']          = in_array( $input['xmlrpc'] ?? '', array( self::XMLRPC_LIMIT, self::XMLRPC_DISABLE ), true ) ? (string) $input['xmlrpc'] : $d['xmlrpc'];
		$out['generic_errors']  = ! empty( $input['generic_errors'] );
		$out['notify']          = in_array( $input['notify'] ?? '', array( self::NOTIFY_NONE, self::NOTIFY_ESCALATED, self::NOTIFY_ALL ), true ) ? (string) $input['notify'] : $d['notify'];
		$email                  = isset( $input['notify_email'] ) && is_string( $input['notify_email'] ) ? sanitize_email( $input['notify_email'] ) : '';
		$out['notify_email']    = is_email( $email ) ? $email : '';
		$out['notify_interval'] = self::int_between( $input['notify_interval'] ?? $d['notify_interval'], 300, 604800 );
		$out['fail2ban']        = ! empty( $input['fail2ban'] );

		$out['log_retention_days'] = self::int_between( $input['log_retention_days'] ?? $d['log_retention_days'], 1, 3650 );

		return $out;
	}

	/**
	 * Valid, unique IP addresses and CIDR ranges from a list or textarea.
	 *
	 * @param mixed $value Lines or array.
	 * @return string[]
	 */
	public static function ip_list( $value ): array {
		$out = array();
		foreach ( self::lines( $value ) as $line ) {
			$entry = Ip::normalize_entry( $line );
			if ( null !== $entry ) {
				$out[] = $entry;
			}
		}

		return array_slice( array_values( array_unique( $out ) ), 0, self::MAX_LIST );
	}

	/**
	 * Non-empty lines without `#` comments from a textarea or array.
	 *
	 * @param mixed $value Lines or array.
	 * @return string[]
	 */
	private static function lines( $value ): array {
		if ( is_string( $value ) ) {
			$value = preg_split( '/[\r\n,]+/', $value );
		}
		$out = array();
		foreach ( (array) $value as $line ) {
			if ( ! is_scalar( $line ) ) {
				continue;
			}
			$line = trim( (string) preg_replace( '/#.*$/', '', (string) $line ) );
			if ( '' !== $line ) {
				$out[] = $line;
			}
		}

		return $out;
	}

	/**
	 * Integer clamped to a range.
	 *
	 * @param mixed $value Raw value.
	 * @param int   $min   Minimum.
	 * @param int   $max   Maximum.
	 */
	private static function int_between( $value, int $min, int $max ): int {
		$value = is_numeric( $value ) ? (int) $value : $min;

		return max( $min, min( $max, $value ) );
	}
}
