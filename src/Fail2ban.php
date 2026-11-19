<?php
/**
 * Log lines for fail2ban.
 *
 * @package Saizul\LoginLimit
 */

namespace Saizul\LoginLimit;

defined( 'ABSPATH' ) || exit;

/**
 * Formats one line per event for the PHP error log.
 *
 * Examples:
 *
 *     wp-login-limit: authentication failure from 203.0.113.5 user="admin" gateway=login
 *     wp-login-limit: lockout from 203.0.113.5 user="admin" gateway=xmlrpc
 *     wp-login-limit: blocked from 203.0.113.5 user="admin" gateway=rest
 *
 * The username is reduced to safe characters so it cannot forge a second
 * line or a different address.
 */
final class Fail2ban {

	const PREFIX = 'wp-login-limit:';
	const EVENTS = array( 'authentication failure', 'lockout', 'blocked' );

	/**
	 * One log line, or an empty string for unknown events.
	 *
	 * @param string $event    One of EVENTS.
	 * @param string $ip       Client IP.
	 * @param string $username Username.
	 * @param string $gateway  login, xmlrpc or rest.
	 */
	public static function line( string $event, string $ip, string $username, string $gateway ): string {
		if ( ! in_array( $event, self::EVENTS, true ) ) {
			return '';
		}
		$ip       = Ip::normalize( $ip ) ?? 'unknown';
		$username = substr( (string) preg_replace( '/[^A-Za-z0-9._@+-]/', '?', $username ), 0, 60 );
		$gateway  = (string) preg_replace( '/[^a-z-]/', '', strtolower( $gateway ) );

		return sprintf( '%s %s from %s user="%s" gateway=%s', self::PREFIX, $event, $ip, $username, '' === $gateway ? 'login' : $gateway );
	}
}
