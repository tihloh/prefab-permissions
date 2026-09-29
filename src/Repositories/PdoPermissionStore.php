<?php

namespace Tihloh\Prefab\Permissions\Repositories;

use PDO;
use RuntimeException;
use Tihloh\Prefab\DatabaseInterface;
use Tihloh\Prefab\PdoDatabaseAdapter;
use Tihloh\Prefab\Permissions\Contracts\ScopedPermissionStoreInterface;

final class PdoPermissionStore implements ScopedPermissionStoreInterface
{
    private DatabaseInterface $database;
    private string $scopedTable;

    public function __construct(
        DatabaseInterface|PDO $database,
        private string $table = 'prefab_subject_permissions',
    ) {
        $this->database = $database instanceof PDO
            ? new PdoDatabaseAdapter($database)
            : $database;

        $this->assertIdentifier($this->table);
        $this->scopedTable = $this->table . '_scoped';
        $this->assertIdentifier($this->scopedTable);
        $this->ensureSchema();
        $this->ensureScopedSchema();
    }

    public function get(string $subjectType, int|string $subjectId): array
    {
        return $this->read(
            $this->table,
            'subject_type = :type AND subject_id = :id',
            ['type' => $subjectType, 'id' => (string)$subjectId],
        );
    }

    public function put(
        string $subjectType,
        int|string $subjectId,
        array $permissions,
    ): void {
        $this->write(
            $this->table,
            [
                'subject_type' => $subjectType,
                'subject_id' => (string)$subjectId,
            ],
            $permissions,
            ['subject_type', 'subject_id'],
        );
    }

    public function remove(string $subjectType, int|string $subjectId): void
    {
        $this->database->statement(
            "DELETE FROM {$this->table} WHERE subject_type=:type AND subject_id=:id",
            ['type' => $subjectType, 'id' => (string)$subjectId],
        );
    }

    public function getScoped(
        string $subjectType,
        int|string $subjectId,
        string $scopeType,
        int|string $scopeId,
    ): array {
        return $this->read(
            $this->scopedTable,
            'subject_type=:type AND subject_id=:id AND scope_type=:scope_type AND scope_id=:scope_id',
            [
                'type' => $subjectType,
                'id' => (string)$subjectId,
                'scope_type' => $scopeType,
                'scope_id' => (string)$scopeId,
            ],
        );
    }

    public function putScoped(
        string $subjectType,
        int|string $subjectId,
        string $scopeType,
        int|string $scopeId,
        array $permissions,
    ): void {
        $this->write(
            $this->scopedTable,
            [
                'subject_type' => $subjectType,
                'subject_id' => (string)$subjectId,
                'scope_type' => $scopeType,
                'scope_id' => (string)$scopeId,
            ],
            $permissions,
            ['subject_type', 'subject_id', 'scope_type', 'scope_id'],
        );
    }

    public function removeScoped(
        string $subjectType,
        int|string $subjectId,
        string $scopeType,
        int|string $scopeId,
    ): void {
        $this->database->statement(
            "DELETE FROM {$this->scopedTable}
             WHERE subject_type=:type AND subject_id=:id AND scope_type=:scope_type AND scope_id=:scope_id",
            [
                'type' => $subjectType,
                'id' => (string)$subjectId,
                'scope_type' => $scopeType,
                'scope_id' => (string)$scopeId,
            ],
        );
    }

    private function read(string $table, string $where, array $params): array
    {
        $sql = $this->driver() === 'sqlsrv'
            ? "SELECT TOP 1 permissions FROM {$table} WHERE {$where}"
            : "SELECT permissions FROM {$table} WHERE {$where} LIMIT 1";

        $rows = $this->database->select($sql, $params);
        $json = $rows[0]['permissions'] ?? null;
        if ($json === null || $json === '') {
            return [];
        }

        $decoded = json_decode((string)$json, true, flags: JSON_THROW_ON_ERROR);
        return is_array($decoded) ? $decoded : [];
    }

    private function write(
        string $table,
        array $keys,
        array $permissions,
        array $conflictColumns,
    ): void {
        $params = $keys;
        $params['permissions'] = json_encode($permissions, JSON_THROW_ON_ERROR);

        $columns = array_keys($keys);
        $columnList = implode(', ', [...$columns, 'permissions', 'created_at', 'updated_at']);
        $valueList = implode(', ', [
            ...array_map(static fn(string $column): string => ':' . $column, $columns),
            ':permissions',
            'CURRENT_TIMESTAMP',
            'CURRENT_TIMESTAMP',
        ]);

        $conflict = implode(', ', $conflictColumns);
        $match = implode(' AND ', array_map(
            static fn(string $column): string => "target.{$column}=source.{$column}",
            $conflictColumns,
        ));
        $source = implode(', ', array_map(
            static fn(string $column): string => ":{$column} AS {$column}",
            $columns,
        ));

        $sql = match ($this->driver()) {
            'sqlite' => "INSERT INTO {$table} ({$columnList})
                VALUES ({$valueList})
                ON CONFLICT({$conflict})
                DO UPDATE SET permissions=excluded.permissions,updated_at=CURRENT_TIMESTAMP",

            'pgsql' => "INSERT INTO {$table} ({$columnList})
                VALUES (" . implode(', ', [
                    ...array_map(static fn(string $column): string => ':' . $column, $columns),
                    'CAST(:permissions AS JSONB)',
                    'CURRENT_TIMESTAMP',
                    'CURRENT_TIMESTAMP',
                ]) . ")
                ON CONFLICT({$conflict})
                DO UPDATE SET permissions=EXCLUDED.permissions,updated_at=CURRENT_TIMESTAMP",

            'sqlsrv' => "MERGE {$table} AS target
                USING (SELECT {$source}, :permissions AS permissions) AS source
                ON {$match}
                WHEN MATCHED THEN
                    UPDATE SET permissions=source.permissions,updated_at=CURRENT_TIMESTAMP
                WHEN NOT MATCHED THEN
                    INSERT ({$columnList})
                    VALUES (" . implode(', ', [
                        ...array_map(static fn(string $column): string => "source.{$column}", $columns),
                        'source.permissions',
                        'CURRENT_TIMESTAMP',
                        'CURRENT_TIMESTAMP',
                    ]) . ");",

            'mysql' => "INSERT INTO {$table} ({$columnList})
                VALUES ({$valueList})
                ON DUPLICATE KEY UPDATE permissions=VALUES(permissions),updated_at=CURRENT_TIMESTAMP",

            default => throw new RuntimeException(
                "Unsupported permission database driver '{$this->driver()}'.",
            ),
        };

        $this->database->statement($sql, $params);
    }

    private function ensureSchema(): void
    {
        $sql = match ($this->driver()) {
            'sqlite' => "CREATE TABLE IF NOT EXISTS {$this->table} (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                subject_type TEXT NOT NULL,
                subject_id TEXT NOT NULL,
                permissions TEXT NOT NULL DEFAULT '{}',
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(subject_type, subject_id)
            )",

            'pgsql' => "CREATE TABLE IF NOT EXISTS {$this->table} (
                id BIGSERIAL PRIMARY KEY,
                subject_type VARCHAR(64) NOT NULL,
                subject_id VARCHAR(191) NOT NULL,
                permissions JSONB NOT NULL DEFAULT '{}'::jsonb,
                created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                CONSTRAINT uq_prefab_subject_permissions UNIQUE (subject_type, subject_id)
            )",

            'sqlsrv' => "IF OBJECT_ID(N'{$this->table}', N'U') IS NULL
                CREATE TABLE {$this->table} (
                    id BIGINT IDENTITY(1,1) PRIMARY KEY,
                    subject_type NVARCHAR(64) NOT NULL,
                    subject_id NVARCHAR(191) NOT NULL,
                    permissions NVARCHAR(MAX) NOT NULL DEFAULT '{}',
                    created_at DATETIME2 NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    updated_at DATETIME2 NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    CONSTRAINT uq_prefab_subject_permissions UNIQUE (subject_type, subject_id)
                )",

            'mysql' => "CREATE TABLE IF NOT EXISTS {$this->table} (
                id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
                subject_type VARCHAR(64) NOT NULL,
                subject_id VARCHAR(191) NOT NULL,
                permissions JSON NOT NULL,
                created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                UNIQUE KEY uq_prefab_subject_permissions (subject_type, subject_id)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci",

            default => throw new RuntimeException(
                "Unsupported permission database driver '{$this->driver()}'.",
            ),
        };

        $this->database->statement($sql);
    }

    private function ensureScopedSchema(): void
    {
        $table = $this->scopedTable;
        $sql = match ($this->driver()) {
            'sqlite' => "CREATE TABLE IF NOT EXISTS {$table} (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                subject_type TEXT NOT NULL,
                subject_id TEXT NOT NULL,
                scope_type TEXT NOT NULL,
                scope_id TEXT NOT NULL,
                permissions TEXT NOT NULL DEFAULT '{}',
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(subject_type, subject_id, scope_type, scope_id)
            )",

            'pgsql' => "CREATE TABLE IF NOT EXISTS {$table} (
                id BIGSERIAL PRIMARY KEY,
                subject_type VARCHAR(64) NOT NULL,
                subject_id VARCHAR(191) NOT NULL,
                scope_type VARCHAR(64) NOT NULL,
                scope_id VARCHAR(191) NOT NULL,
                permissions JSONB NOT NULL DEFAULT '{}'::jsonb,
                created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(subject_type, subject_id, scope_type, scope_id)
            )",

            'sqlsrv' => "IF OBJECT_ID(N'{$table}', N'U') IS NULL
                CREATE TABLE {$table} (
                    id BIGINT IDENTITY(1,1) PRIMARY KEY,
                    subject_type NVARCHAR(64) NOT NULL,
                    subject_id NVARCHAR(191) NOT NULL,
                    scope_type NVARCHAR(64) NOT NULL,
                    scope_id NVARCHAR(191) NOT NULL,
                    permissions NVARCHAR(MAX) NOT NULL DEFAULT '{}',
                    created_at DATETIME2 NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    updated_at DATETIME2 NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    CONSTRAINT uq_prefab_subject_permissions_scoped UNIQUE
                        (subject_type, subject_id, scope_type, scope_id)
                )",

            'mysql' => "CREATE TABLE IF NOT EXISTS {$table} (
                id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
                subject_type VARCHAR(64) NOT NULL,
                subject_id VARCHAR(191) NOT NULL,
                scope_type VARCHAR(64) NOT NULL,
                scope_id VARCHAR(191) NOT NULL,
                permissions JSON NOT NULL,
                created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                UNIQUE KEY uq_prefab_subject_permissions_scoped
                    (subject_type, subject_id, scope_type, scope_id),
                INDEX idx_prefab_permission_scope (scope_type, scope_id)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci",

            default => throw new RuntimeException(
                "Unsupported permission database driver '{$this->driver()}'.",
            ),
        };

        $this->database->statement($sql);
    }

    private function driver(): string
    {
        return $this->database->driver();
    }

    private function assertIdentifier(string $identifier): void
    {
        if (!preg_match('/^[A-Za-z_][A-Za-z0-9_]*$/', $identifier)) {
            throw new RuntimeException("Unsafe SQL identifier: {$identifier}");
        }
    }
}
