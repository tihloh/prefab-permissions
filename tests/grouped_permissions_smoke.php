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
                        "description"=>"Manage users across authorized contexts.",
                        "default"=>false,
                        "scopes"=>["organization"],
                        "scope_descriptions"=>[
                            "organization"=>"Manage users in this organization.",
                        ],
                    ],
                    "users.view"=>[
                        "name"=>"View Users",
                        "description"=>"View user records.",
                        "default"=>false,
                        "scopes"=>["global","organization"],
                        "scope_descriptions"=>[
                            "global"=>"View user records across the platform.",
                            "organization"=>"View user records in this organization.",
                        ],
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

    // Both kinds of description are independent optional presentation metadata.
    checkGrouped($definitions->description("users.view")==="View user records.",
        "General description should remain available alongside scoped text.");
    checkGrouped($definitions->description("users.view","global")==="View user records across the platform.",
        "Global scope must use its own description.");
    checkGrouped($definitions->description("users.view","organization")==="View user records in this organization.",
        "Organization scope must use its own description.");
    checkGrouped($definitions->scopeDescriptions("users.view")===
        ["global"=>"View user records across the platform.",
         "organization"=>"View user records in this organization."],
        "Explicit per-scope descriptions should remain independently addressable.");
    checkGrouped($definitions->description("logs.view","global")==="View platform audit logs.",
        "Missing scope text should fall back to the general description.");
    checkGrouped($definitions->description("missing","global")===null,
        "Unknown permissions must not invent descriptions.");

    $scopeOnly=PermissionDefinitions::from([
        "report.export"=>[
            "name"=>"Export Reports",
            "scopes"=>["global","organization"],
            "scope_descriptions"=>[
                "global"=>"Export reports across the platform.",
                "organization"=>"Export reports for an organization.",
            ],
        ],
        "reports.view"=>[
            "name"=>"View Reports",
            "scopes"=>["global","organization"],
            "description"=>"  Default report viewing.  ",
            "scope_descriptions"=>["organization"=>"  "],
        ],
        "bare"=>["name"=>"Bare Permission"],
    ]);
    checkGrouped($scopeOnly->description("report.export")===null
        && $scopeOnly->description("report.export","organization")==="Export reports for an organization.",
        "A permission may declare only scoped descriptions without a general description.");
    checkGrouped($scopeOnly->description("reports.view","organization")==="Default report viewing."
        && $scopeOnly->scopeDescriptions("reports.view")===[],
        "Blank scoped descriptions should use general fallback.");
    checkGrouped($scopeOnly->description("bare")===null
        && $scopeOnly->description("bare","global")===null
        && $scopeOnly->scopeDescriptions("bare")===[],
        "Both description levels must remain optional.");

    foreach([
        ["users.view"=>["scopes"=>["global"],"scope_descriptions"=>"wrong"]],
        ["users.view"=>["scopes"=>["global"],"scope_descriptions"=>["organization"=>"not supported"]]],
        ["users.view"=>["scopes"=>["organization"],"scope_descriptions"=>["organization"=>false]]],
        ["users.view"=>["scope_descriptions"=>[123=>"numeric scope"]]],
    ] as $invalidDescriptions){
        $threw=false;
        try{PermissionDefinitions::from($invalidDescriptions);}
        catch(\InvalidArgumentException){$threw=true;}
        checkGrouped($threw,"Invalid scope descriptions must be rejected.");
    }

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
    checkGrouped($permissions->permissionDescription("users.view")==="View user records."
        && $permissions->permissionDescription("users.view","organization")==="View user records in this organization."
        && $permissions->permissionDescription("logs.view","global")==="View platform audit logs.",
        "Manager must expose effective descriptions with general fallback.");
    checkGrouped($permissions->permissionScopeDescriptions("users.view")===
        $definitions->scopeDescriptions("users.view"),
        "Manager must expose explicit scope descriptions without inserting fallback values.");
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
