<?php

namespace Tihloh\Prefab\Permissions\Contracts;

interface ScopedPermissionStoreInterface extends PermissionStoreInterface
{
    public function getScoped(
        string $subjectType,
        int|string $subjectId,
        string $scopeType,
        int|string $scopeId,
    ): array;

    public function putScoped(
        string $subjectType,
        int|string $subjectId,
        string $scopeType,
        int|string $scopeId,
        array $permissions,
    ): void;

    public function removeScoped(
        string $subjectType,
        int|string $subjectId,
        string $scopeType,
        int|string $scopeId,
    ): void;
}
