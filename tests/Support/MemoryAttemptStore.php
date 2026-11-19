<?php
declare(strict_types=1);

namespace Saizul\LoginLimit\Tests\Support;

use Saizul\LoginLimit\Record;
use Saizul\LoginLimit\Store\AttemptStore;

/**
 * In-memory attempt store with the same behaviour as DbAttemptStore.
 */
final class MemoryAttemptStore implements AttemptStore {

	/** @var array<string,array<string,mixed>> */
	public $rows = array();

	public function get( string $key ): ?Record {
		return isset( $this->rows[ $key ] ) ? Record::from_array( $this->rows[ $key ] ) : null;
	}

	public function put( Record $record, int $now ): void {
		$this->rows[ $record->key() ] = array_merge( $record->to_array(), array( 'updated_at' => $now ) );
	}

	public function delete( string $key ): bool {
		$found = isset( $this->rows[ $key ] );
		unset( $this->rows[ $key ] );
		return $found;
	}

	public function delete_all(): int {
		$count      = count( $this->rows );
		$this->rows = array();
		return $count;
	}

	public function locked( int $now ): array {
		$rows = array_filter(
			$this->rows,
			static function ( array $row ) use ( $now ) {
				return $row['locked_until'] > $now;
			}
		);
		uasort(
			$rows,
			static function ( $a, $b ) {
				return $b['last_lockout'] <=> $a['last_lockout'];
			}
		);
		return array_values( array_map( array( Record::class, 'from_array' ), $rows ) );
	}

	public function purge( int $before, int $now ): int {
		$count = 0;
		foreach ( $this->rows as $key => $row ) {
			if ( $row['updated_at'] < $before && $row['locked_until'] <= $now ) {
				unset( $this->rows[ $key ] );
				++$count;
			}
		}
		return $count;
	}
}
