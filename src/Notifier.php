<?php
/**
 * Admin email on lockouts, throttled.
 *
 * @package Saizul\LoginLimit
 */

namespace Saizul\LoginLimit;

defined( 'ABSPATH' ) || exit;

/**
 * Sends at most one email per interval. Lockouts in between are counted and
 * mentioned in the next email, so a large attack does not flood the inbox.
 */
final class Notifier {

	const STATE_OPTION = 'wp_login_limit_notify_state';

	/**
	 * Settings.
	 *
	 * @var array<string,mixed>
	 */
	private $settings;

	/**
	 * Constructor.
	 *
	 * @param array<string,mixed> $settings Settings.
	 */
	public function __construct( array $settings ) {
		$this->settings = array_merge( Settings::defaults(), $settings );
	}

	/**
	 * Notify about a new lockout if the settings and the throttle allow it.
	 *
	 * @param Lockout $lockout Lockout.
	 * @param int     $now     Current time.
	 * @return bool Whether an email was sent.
	 */
	public function lockout( Lockout $lockout, int $now ): bool {
		$mode = (string) $this->settings['notify'];
		if ( Settings::NOTIFY_NONE === $mode || ( Settings::NOTIFY_ESCALATED === $mode && $lockout->level < 2 ) ) {
			return false;
		}

		$state   = get_option( self::STATE_OPTION, array() );
		$state   = is_array( $state ) ? $state : array();
		$last    = (int) ( $state['last'] ?? 0 );
		$pending = (int) ( $state['pending'] ?? 0 );
		if ( $last > 0 && $now - $last < (int) $this->settings['notify_interval'] ) {
			update_option(
				self::STATE_OPTION,
				array(
					'last'    => $last,
					'pending' => $pending + 1,
				),
				false
			);
			return false;
		}

		$to = (string) $this->settings['notify_email'];
		if ( '' === $to ) {
			$to = (string) get_option( 'admin_email' );
		}
		if ( '' === $to ) {
			return false;
		}

		$site    = wp_specialchars_decode( (string) get_option( 'blogname' ), ENT_QUOTES );
		$subject = sprintf(
			/* translators: 1: site name, 2: IP address or username. */
			__( '[%1$s] Login lockout: %2$s', 'wp-login-limit' ),
			$site,
			Lockout::REASON_USER === $lockout->reason ? $lockout->username : $lockout->ip
		);

		/**
		 * Filters whether to send a lockout email.
		 *
		 * @param bool    $send    Send it.
		 * @param Lockout $lockout Lockout.
		 */
		if ( ! apply_filters( 'login_limit_send_notification', true, $lockout ) ) {
			return false;
		}

		$sent = (bool) wp_mail( $to, $subject, $this->body( $lockout, $pending ) );
		update_option(
			self::STATE_OPTION,
			array(
				'last'    => $now,
				'pending' => 0,
			),
			false
		);

		return $sent;
	}

	/**
	 * Plain text body.
	 *
	 * @param Lockout $lockout Lockout.
	 * @param int     $pending Lockouts since the last email that were not mailed.
	 */
	public function body( Lockout $lockout, int $pending ): string {
		$what  = Lockout::REASON_USER === $lockout->reason
			? __( 'A username was locked out after too many failed login attempts.', 'wp-login-limit' )
			: __( 'An IP address was locked out after too many failed login attempts.', 'wp-login-limit' );
		$lines = array(
			$what,
			'',
			/* translators: %s: IP address. */
			sprintf( __( 'IP address: %s', 'wp-login-limit' ), '' === $lockout->ip ? '-' : $lockout->ip ),
			/* translators: %s: username. */
			sprintf( __( 'Username tried: %s', 'wp-login-limit' ), '' === $lockout->username ? '-' : $lockout->username ),
			/* translators: %s: login, xmlrpc or rest. */
			sprintf( __( 'Via: %s', 'wp-login-limit' ), '' === $lockout->gateway ? '-' : $lockout->gateway ),
			/* translators: %d: minutes. */
			sprintf( __( 'Duration: %d minutes', 'wp-login-limit' ), (int) ceil( $lockout->duration / 60 ) ),
			/* translators: %d: lockout number. */
			sprintf( __( 'Lockout number: %d', 'wp-login-limit' ), $lockout->level ),
		);
		if ( $pending > 0 ) {
			$lines[] = '';
			/* translators: %d: number of lockouts. */
			$lines[] = sprintf( _n( '%d more lockout happened since the last email.', '%d more lockouts happened since the last email.', $pending, 'wp-login-limit' ), $pending );
		}
		$lines[] = '';
		$lines[] = __( 'Review lockouts and settings:', 'wp-login-limit' );
		$lines[] = admin_url( 'options-general.php?page=wp-login-limit' );

		return implode( "\n", $lines ) . "\n";
	}
}
