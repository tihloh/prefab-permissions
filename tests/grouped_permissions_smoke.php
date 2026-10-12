<?php
/** Run: php tests/grouped_permissions_smoke.php
 * No composer dependencies or database are needed for this smoke test.
 */
namespace Tihloh\Prefab {
    final class PrefabRuntime
    {
        public static function register(string $name,object $service): void {}
        public static function recordResolution(string $module,string $key,string $source,array $meta=[]): void {}
        public static function traceStart(string $module,string $action): void {}
        public static function traceEnd(array $meta=[]): void {}
    }
}

namespace {
    require_once dirname(__DIR__)."/src/Contracts/PermissionStoreInterface.php";
    require_once dirname(__DIR__)."/src/Contracts/ScopedPermissionStoreInterface.php";
    require_once dirname(__DIR__)."/src/Contracts/PermissionSubjectInterface.php";
    require_once dirname(__DIR__)."/src/DTOs/PermissionResult.php";
    require_once dirname(__DIR__)."/src/Services/PermissionDefinitions.php";
    require_once dirname(__DIR__)."/src/Services/PermissionManager.php";

    use Tihloh\Prefab\Permissions\Contracts\ScopedPermissionStoreInterface;
    use Tihloh\Prefab\Permissions\Services\PermissionDefinitions;
    use Tihloh\Prefab\Permissions\Services\PermissionManager;

    function checkGrouped(bool $value,string $message): void
    {
        if(!$value) throw new \RuntimeException($message);
    }

    $catalog=[
        "permissions"=>[
            "groups"=>[
                "Users & Access"=>[
                    "users.manage"=>[
                        "name"=>"Manage Users",
                        "description"=>"Manage users in a permitted organization.",
                        "default"=>false,
                        "scopes"=>["organization"],
                    ],
                    "users.view"=>[
                        "name"=>"View Users",
                        "description"=>"View user records.",
                        "default"=>false,
                        "scopes"=>["global","organization"],
                    ],
                ],
                "System"=>[
                    "logs.view"=>[
                        "name"=>"View Logs",
                        "description"=>"View platform audit logs.",
                        "default"=>false,
                        "scopes"=>["global"],
                    ],
                ],
            ],
        ],
    ];

    $definitions=PermissionDefinitions::from($catalog);
    checkGrouped(count($definitions->all())===3,"Catalog must normalize to three flat definitions.");
    checkGrouped($definitions->has("users.manage"),"Permission lookup failed.");
    checkGrouped($definitions->group("users.manage")==="Users & Access","Group/category not retained.");
    checkGrouped($definitions->groups()===["Users & Access","System"],"Group order changed.");
    checkGrouped(isset($definitions->grouped()["Users & Access"]["users.view"]),"Grouping failed.");
    checkGrouped($definitions->scopes("users.manage")===["organization"],"Scopes changed.");
    checkGrouped($definitions->supportsScope("logs.view","global"),"Global support missing.");
    checkGrouped(!$definitions->supportsScope("logs.view","organization"),"Unsupported organization scope accepted.");

    $direct=new PermissionDefinitions($catalog);
    checkGrouped($direct->all()===$definitions->all(),"Direct constructor did not normalize.");
    $flat=["users.manage"=>["name"=>"Manage Users","default"=>false]];
    checkGrouped(PermissionDefinitions::from($flat)->all()===$flat,"Legacy flat config changed.");

    $paths=[];
    try{
        $temp=sys_get_temp_dir()."/prefab_grouped_".bin2hex(random_bytes(8));
        $paths=[$temp.".php",$temp.".json"];
        file_put_contents($paths[0],"<?php return ".var_export($catalog,true).";");
        file_put_contents($paths[1],json_encode($catalog,JSON_THROW_ON_ERROR));
        foreach($paths as $path){
            $fromFile=PermissionDefinitions::fromFile($path);
            checkGrouped($fromFile->all()===$definitions->all(),
                "Grouped catalog file did not load: ".$path);
        }
    }finally{
        foreach($paths as $path) if(is_file($path)) unlink($path);
    }

    foreach([
        ["permissions"=>["groups"=>["Office"=>["users.manage"=>[], "users.view"=>[]],
                                   "Other"=>["users.manage"=>[]]]]],
        ["permissions"=>["groups"=>["Office"=>"invalid"]]],
        ["permissions"=>["invalid"=>[]]],
        ["permissions"=>["groups"=>["Office"=>["users.manage"=>["group"=>"Wrong"]]]]],
    ] as $invalid){
        $threw=false;
        try{ PermissionDefinitions::from($invalid); }
        catch(\InvalidArgumentException){ $threw=true; }
        checkGrouped($threw,"Invalid grouped catalog was accepted.");
    }

    final class MemoryPermissionStore implements ScopedPermissionStoreInterface
    {
        public array $global=[
            "user:1"=>["users.manage"=>true],
            "group:g_global"=>["users.manage"=>true,"users.view"=>true,"logs.view"=>true],
        ];
        public array $scoped=[
            "organization:GO:group:g_office"=>["users.manage"=>true],
            "organization:PBO:group:g_office"=>["users.manage"=>false],
        ];
        public function get(string $subjectType,int|string $subjectId): array
        {
            return $this->global[$subjectType.":".$subjectId]??[];
        }
        public function put(string $subjectType,int|string $subjectId,array $permissions): void {}
        public function remove(string $subjectType,int|string $subjectId): void {}
        public function getScoped(string $subjectType,int|string $subjectId,string $scopeType,int|string $scopeId): array
        {
            return $this->scoped[$scopeType.":".$scopeId.":".$subjectType.":".$subjectId]??[];
        }
        public function putScoped(string $subjectType,int|string $subjectId,string $scopeType,int|string $scopeId,array $permissions): void {}
        public function removeScoped(string $subjectType,int|string $subjectId,string $scopeType,int|string $scopeId): void {}
    }
    $permissions=new PermissionManager($definitions,new MemoryPermissionStore());
    checkGrouped(!$permissions->can("1","users.manage",["g_global"]),
        "Organization-only permission leaked through a global user or group rule.");
    checkGrouped($permissions->can("1","users.manage",["g_office"],"organization","GO"),
        "Office group permission should be allowed in GO.");
    checkGrouped(!$permissions->can("1","users.manage",["g_office"],"organization","PBO"),
        "Office permission should not grant access in PBO.");
    checkGrouped(!$permissions->can("1","users.manage",["g_global"],"organization","GO"),
        "Legacy global user override must not grant organization-only permissions.");
    checkGrouped($permissions->can("1","logs.view",["g_global"]),
        "Global-only permission should work through global group.");
    checkGrouped($permissions->can("1","logs.view",["g_global"],"organization","GO"),
        "Global grant should still work when checking an organization resource.");
    checkGrouped($permissions->can("1","users.view",["g_global"],"organization","GO"),
        "Dual-scope permission should honor global group inside an organization.");

    echo "Prefab grouped catalog and permission scope smoke checks passed.\n";
}
