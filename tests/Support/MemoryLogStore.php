<?php
declare(strict_types=1);

namespace Saizul\LoginLimit\Tests\Support;

use Saizul\LoginLimit\Store\LogStore;

/**
 * In-memory lockout log.
 */
final class MemoryLogStore implements LogStore {

	/** @var array<int,array<string,mixed>> */
	public $entries = array();

	public function add( array $entry ): void {
		$this->entries[] = array_merge(
			array(
				'time'     => 0,
				'event'    => '',
				'ip'       => '',
				'username' => '',
				'gateway'  => '',
				'duration' => 0,
				'level'    => 0,
			),
			$entry
		);
	}

	public function recent( int $limit, int $offset = 0 ): array {
		return array_slice( array_reverse( $this->entries ), $offset, $limit );
	}

	public function count(): int {
		return count( $this->entries );
	}

	public function clear(): void {
		$this->entries = array();
	}

	public function purge( int $before ): int {
		$count         = count( $this->entries );
		$this->entries = array_values(
			array_filter(
				$this->entries,
				static function ( array $entry ) use ( $before ) {
					return $entry['time'] >= $before;
				}
			)
		);
		return $count - count( $this->entries );
	}

	/** @return string[] */
	public function events(): array {
		return array_column( $this->entries, 'event' );
	}
}
