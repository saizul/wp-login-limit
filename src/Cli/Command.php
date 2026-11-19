<?php
/**
 * WP-CLI command.
 *
 * @package Saizul\LoginLimit
 */

namespace Saizul\LoginLimit\Cli;

use Saizul\LoginLimit\Ip;
use Saizul\LoginLimit\Limiter;
use Saizul\LoginLimit\Plugin;
use Saizul\LoginLimit\Record;

defined( 'ABSPATH' ) || exit;

/**
 * Unlock clients and inspect lockouts.
 *
 * ## EXAMPLES
 *
 *     wp login-limit unlock 203.0.113.5
 *     wp login-limit unlock admin
 *     wp login-limit unlock --all
 *     wp login-limit list
 *     wp login-limit log --limit=20
 *     wp login-limit check 203.0.113.5 --user=admin
 */
final class Command {

	/**
	 * Plugin.
	 *
	 * @var Plugin
	 */
	private $plugin;

	/**
	 * Constructor.
	 *
	 * @param Plugin $plugin Plugin.
	 */
	public function __construct( Plugin $plugin ) {
		$this->plugin = $plugin;
	}

	/**
	 * Remove lockouts and failure counters.
	 *
	 * ## OPTIONS
	 *
	 * [<target>...]
	 * : IP addresses, IPv6 networks (2001:db8::/64) or usernames.
	 *
	 * [--all]
	 * : Unlock everyone.
	 *
	 * @param string[]             $args       Positional arguments.
	 * @param array<string,string> $assoc_args Options.
	 */
	public function unlock( $args, $assoc_args ): void {
		$limiter = $this->plugin->limiter();
		if ( ! empty( $assoc_args['all'] ) ) {
			$count = $limiter->unlock_all();
			\WP_CLI::success( sprintf( 'Removed %d lockout and counter records.', $count ) );
			return;
		}
		if ( array() === $args ) {
			\WP_CLI::error( 'Give at least one IP address or username, or --all.' );
			return;
		}
		$done = 0;
		foreach ( $args as $target ) {
			if ( 1 === $limiter->unlock( (string) $target ) ) {
				++$done;
				\WP_CLI::line( sprintf( 'Unlocked %s.', $target ) );
			} else {
				\WP_CLI::warning( sprintf( 'Nothing to unlock for %s.', $target ) );
			}
		}
		\WP_CLI::success( sprintf( 'Unlocked %d of %d.', $done, count( $args ) ) );
	}

	/**
	 * List active lockouts.
	 *
	 * ## OPTIONS
	 *
	 * [--format=<format>]
	 * : Output format.
	 * ---
	 * default: table
	 * options:
	 *   - table
	 *   - csv
	 *   - json
	 *   - yaml
	 *   - count
	 * ---
	 *
	 * @subcommand list
	 *
	 * @param string[]             $args       Positional arguments.
	 * @param array<string,string> $assoc_args Options.
	 */
	public function list_( $args, $assoc_args ): void {
		$limiter = $this->plugin->limiter();
		$now     = $limiter->now();
		$rows    = array_map(
			static function ( Record $record ) use ( $now ) {
				return array(
					'type'         => $record->kind,
					'value'        => $record->value,
					'locked_until' => gmdate( 'Y-m-d H:i:s', $record->locked_until ) . ' UTC',
					'seconds_left' => max( 0, $record->locked_until - $now ),
					'lockouts'     => $record->lockouts,
				);
			},
			$limiter->locked()
		);
		\WP_CLI\Utils\format_items( $assoc_args['format'] ?? 'table', $rows, array( 'type', 'value', 'locked_until', 'seconds_left', 'lockouts' ) );
	}

	/**
	 * Show the lockout log.
	 *
	 * ## OPTIONS
	 *
	 * [--limit=<number>]
	 * : Number of entries.
	 * ---
	 * default: 50
	 * ---
	 *
	 * [--format=<format>]
	 * : Output format.
	 * ---
	 * default: table
	 * options:
	 *   - table
	 *   - csv
	 *   - json
	 *   - yaml
	 *   - count
	 * ---
	 *
	 * @param string[]             $args       Positional arguments.
	 * @param array<string,string> $assoc_args Options.
	 */
	public function log( $args, $assoc_args ): void {
		$limit = max( 1, min( 10000, (int) ( $assoc_args['limit'] ?? 50 ) ) );
		$rows  = array_map(
			static function ( array $entry ) {
				return array(
					'time'     => gmdate( 'Y-m-d H:i:s', (int) $entry['time'] ) . ' UTC',
					'event'    => (string) $entry['event'],
					'ip'       => (string) $entry['ip'],
					'username' => (string) $entry['username'],
					'gateway'  => (string) $entry['gateway'],
					'duration' => (int) $entry['duration'],
					'level'    => (int) $entry['level'],
				);
			},
			$this->plugin->log()->recent( $limit )
		);
		\WP_CLI\Utils\format_items( $assoc_args['format'] ?? 'table', $rows, array( 'time', 'event', 'ip', 'username', 'gateway', 'duration', 'level' ) );
	}

	/**
	 * Show whether an IP (and optionally a username) may log in.
	 *
	 * ## OPTIONS
	 *
	 * <ip>
	 * : Client IP address.
	 *
	 * [--user=<username>]
	 * : Username to check as well.
	 *
	 * @param string[]             $args       Positional arguments.
	 * @param array<string,string> $assoc_args Options.
	 */
	public function check( $args, $assoc_args ): void {
		$ip = (string) Ip::normalize( (string) ( $args[0] ?? '' ) );
		if ( '' === $ip ) {
			\WP_CLI::error( 'Give a valid IPv4 or IPv6 address.' );
			return;
		}
		$limiter  = $this->plugin->limiter();
		$username = Limiter::normalize_username( (string) ( $assoc_args['user'] ?? '' ) );
		$lockout  = $limiter->check( $ip, $username );
		$now      = $limiter->now();
		if ( $limiter->is_allowlisted( $ip ) ) {
			\WP_CLI::line( sprintf( '%s is on the allowlist: never counted or locked out.', $ip ) );
			return;
		}
		if ( null !== $lockout ) {
			if ( 'denylist' === $lockout->reason ) {
				\WP_CLI::line( sprintf( '%s is on the denylist: login is never allowed.', $ip ) );
				return;
			}
			\WP_CLI::line( sprintf( 'Locked (%s) for %d more seconds, lockout number %d.', $lockout->reason, $lockout->remaining( $now ), $lockout->level ) );
			return;
		}
		$remaining = $limiter->policy()->remaining(
			$this->record( Record::KIND_IP, $limiter->network( $ip ) ),
			(int) $limiter->settings()['ip_max_retries'],
			$now
		);
		\WP_CLI::line( sprintf( 'Not locked. %d failed attempts left for %s.', $remaining, $limiter->network( $ip ) ) );
	}

	/**
	 * Stored record, or an empty one.
	 *
	 * @param string $kind  Kind.
	 * @param string $value Value.
	 */
	private function record( string $kind, string $value ): Record {
		return $this->plugin->attempts()->get( Record::make_key( $kind, $value ) ) ?? new Record( $kind, $value );
	}
}
