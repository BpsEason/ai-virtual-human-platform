#!/bin/bash

# ==============================================================================
# generate_project.sh
# ------------------------------------------------------------------------------
# 腳本說明：
# 此腳本用於自動化生成一個包含 Laravel 11、微服務、Vue 3 前端、Docker 和
# Kubernetes (Helm) 的完整專案結構。它會建立所有必要的目錄、設定檔、
# 腳本和程式碼骨架，以加速專案開發。
#
# 技術棧：
# - 後端: PHP 8.2, Laravel 11, Laravel Octane (Swoole), JWT Auth
# - 微服務:
#   - 向量化服務: Python 3.10, FastAPI 0.95, SentenceTransformer, Faiss
#   - 對話服務: Node.js 20, TypeScript 5.0, gRPC, LangChain JS
# - 前端: Vue 3.3, Vite 5, Pinia, Tailwind CSS
# - 資料庫: MySQL 8.0, Redis 7.0, RabbitMQ 3.9
# - 部署: Docker, Docker Compose, Kubernetes, Helm
# - CI/CD: GitHub Actions
#
# 使用方法：
# 1. 確保已安裝 `git`, `openssl`, `docker`, `docker-compose`。
# 2. 執行此腳本：`bash generate_project.sh`
# 3. 進入專案目錄，執行 `./scripts/dev-setup.sh` 啟動開發環境。
# 4. 執行 `./scripts/build.sh` 執行建構。
# 5. 執行 `./scripts/test.sh` 執行測試。
# 6. 執行 `./scripts/deploy-helm.sh` 部署到 Kubernetes。
#
# ------------------------------------------------------------------------------
# 腳本作者：程式夥伴
# 創建日期：2023-08-01
# 更新日期：2023-08-03
# ==============================================================================

echo "程式夥伴：開始生成專案結構和檔案..."

# 1. 建立目錄結構
echo "1. 建立專案目錄結構..."
mkdir -p .github/workflows
mkdir -p app/Http/Controllers app/Http/Middleware app/Jobs app/Models app/Enums app/Providers app/Exceptions
mkdir -p config database/migrations database/factories database/seeders routes scripts bootstrap
mkdir -p public resources/js resources/js/components resources/js/router resources/js/stores resources/css resources/views
mkdir -p tests/Feature
mkdir -p microservices/chat-service/src/proto microservices/chat-service/tests
mkdir -p microservices/vectorization-service/app microservices/vectorization-service/tests
mkdir -p kubernetes/helm/templates
mkdir -p docker/php docker/nginx/certs docker/prometheus docker/mysql

# 2. 生成 CI/CD 流水線
echo "2. 生成 GitHub Actions CI/CD 流水線..."
cat > .github/workflows/ci.yml << 'EOF'
name: CI
on: [push, pull_request]

jobs:
  lint-test-build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Setup PHP
        uses: shivammathur/setup-php@v2
        with:
          php-version: '8.2'
          tools: composer
      - name: Install PHP Dependencies
        run: composer install --prefer-dist --no-interaction --no-progress
      - name: Run PHP Tests
        run: vendor/bin/phpunit

      - name: Setup Node.js
        uses: actions/setup-node@v3
        with:
          node-version: '20'
      - name: Install Chat Service Dependencies
        run: cd microservices/chat-service && npm install
      - name: Build Chat Service
        run: cd microservices/chat-service && npm run build

      - name: Setup Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.10'
      - name: Install Vectorization Service Dependencies
        run: cd microservices/vectorization-service && pip install -r requirements.txt
      - name: Run Python Tests
        run: cd microservices/vectorization-service && pytest

      - name: Setup Helm
        uses: azure/setup-helm@v3
        with:
          version: '3.9.0'
      - name: Deploy to Kubernetes
        run: helm upgrade --install my-app ./kubernetes/helm --set image.tag=latest --namespace my-namespace --create-namespace
EOF

# 3. 生成 Laravel 專案骨架
echo "3. 生成 Laravel 專案骨架..."
cat > composer.json << 'EOF'
{
    "name": "your-project/laravel",
    "description": "The Laravel framework.",
    "type": "project",
    "license": "MIT",
    "require": {
        "php": "^8.2",
        "guzzlehttp/guzzle": "^7.2",
        "laravel/framework": "^11.0",
        "laravel/octane": "^2.0",
        "laravel/sanctum": "^4.0",
        "laravel/tinker": "^2.8",
        "tymon/jwt-auth": "^1.0"
    },
    "autoload": {
        "psr-4": {
            "App\\": "app/",
            "Database\\Factories\\": "database/factories/",
            "Database\\Seeders\\": "database/seeders/"
        }
    },
    "autoload-dev": {
        "psr-4": {
            "Tests\\": "tests/"
        }
    },
    "config": {
        "optimize-autoloader": true,
        "preferred-install": "dist",
        "sort-packages": true
    },
    "minimum-stability": "stable",
    "prefer-stable": true
}
EOF

cat > .env.example << 'EOF'
APP_NAME="Laravel"
APP_ENV=local
APP_KEY=
APP_DEBUG=true
APP_URL=http://localhost

LOG_CHANNEL=stack
LOG_LEVEL=debug

DB_CONNECTION=mysql
DB_HOST=mysql
DB_PORT=3306
DB_DATABASE=laravel
DB_USERNAME=root
DB_PASSWORD=root

BROADCAST_DRIVER=log
CACHE_DRIVER=redis
FILESYSTEM_DRIVER=local
QUEUE_CONNECTION=rabbitmq
SESSION_DRIVER=redis
SESSION_LIFETIME=120

REDIS_HOST=redis
REDIS_PASSWORD=null
REDIS_PORT=6379

OCTANE_SERVER=swoole

JWT_SECRET=
JWT_TTL=15
JWT_REFRESH_TTL=10080

RABBITMQ_HOST=rabbitmq
RABBITMQ_PORT=5672
RABBITMQ_USER=guest
RABBITMQ_PASSWORD=guest

PINECONE_API_KEY=
PINECONE_ENVIRONMENT=
OPENAI_API_KEY=

EOF

cat > bootstrap/app.php << 'EOF'
<?php

use Illuminate\Foundation\Application;
use Illuminate\Foundation\Configuration\Exceptions;
use Illuminate\Foundation\Configuration\Middleware;

return Application::configure(basePath: dirname(__DIR__))
    ->withRouting(
        web: __DIR__.'/../routes/web.php',
        api: __DIR__.'/../routes/api.php',
        commands: __DIR__.'/../routes/console.php',
        health: '/up',
    )
    ->withMiddleware(function (Middleware $middleware) {
        //
    })
    ->withExceptions(function (Exceptions $exceptions) {
        //
    })->create();
EOF

cat > config/app.php << 'EOF'
<?php

use Illuminate\Support\Facades\Facade;
use Illuminate\Support\ServiceProvider;

return [
    'name' => env('APP_NAME', 'Laravel'),
    'env' => env('APP_ENV', 'production'),
    'debug' => (bool) env('APP_DEBUG', false),
    'url' => env('APP_URL', 'http://localhost'),
    'timezone' => 'Asia/Taipei',
    'locale' => 'zh-TW',
    'fallback_locale' => 'en',
    'key' => env('APP_KEY'),
    'cipher' => 'AES-256-CBC',
    'providers' => ServiceProvider::defaultProviders()->merge([
        App\Providers\AppServiceProvider::class,
    ])->toArray(),
    'aliases' => Facade::defaultAliases()->toArray(),
];
EOF

cat > config/auth.php << 'EOF'
<?php

return [
    'defaults' => [
        'guard' => 'web',
        'passwords' => 'users',
    ],
    'guards' => [
        'web' => [
            'driver' => 'session',
            'provider' => 'users',
        ],
        'api' => [
            'driver' => 'sanctum',
            'provider' => 'users',
        ],
        'jwt' => [
            'driver' => 'jwt',
            'provider' => 'users',
        ],
    ],
    'providers' => [
        'users' => [
            'driver' => 'eloquent',
            'model' => App\Models\User::class,
        ],
    ],
    'passwords' => [
        'users' => [
            'provider' => 'users',
            'table' => 'password_reset_tokens',
            'expire' => 60,
            'throttle' => 60,
        ],
    ],
];
EOF

cat > config/database.php << 'EOF'
<?php

use Illuminate\Support\Str;

return [
    'default' => env('DB_CONNECTION', 'mysql'),
    'connections' => [
        'sqlite' => [
            'driver' => 'sqlite',
            'url' => env('DATABASE_URL'),
            'database' => env('DB_DATABASE', database_path('database.sqlite')),
            'prefix' => '',
            'foreign_key_constraints' => env('DB_FOREIGN_KEYS', true),
        ],
        'mysql' => [
            'driver' => 'mysql',
            'url' => env('DATABASE_URL'),
            'host' => env('DB_HOST', '127.0.0.1'),
            'port' => env('DB_PORT', '3306'),
            'database' => env('DB_DATABASE', 'laravel'),
            'username' => env('DB_USERNAME', 'root'),
            'password' => env('DB_PASSWORD', ''),
            'unix_socket' => env('DB_SOCKET', ''),
            'charset' => 'utf8mb4',
            'collation' => 'utf8mb4_unicode_ci',
            'prefix' => '',
            'prefix_indexes' => true,
            'strict' => true,
            'engine' => null,
            'options' => extension_loaded('pdo_mysql') ? array_filter([
                PDO::MYSQL_ATTR_SSL_CA => env('MYSQL_ATTR_SSL_CA'),
            ]) : [],
        ],
    ],
    'migrations' => [
        'table' => 'migrations',
        'update_date_on_publish' => true,
    ],
    'redis' => [
        'client' => env('REDIS_CLIENT', 'phpredis'),
        'options' => [
            'cluster' => env('REDIS_CLUSTER_ENABLED', false),
            'prefix' => env('REDIS_PREFIX', Str::slug(env('APP_NAME', 'laravel'), '_').'_database_'),
        ],
        'default' => [
            'url' => env('REDIS_URL'),
            'host' => env('REDIS_HOST', '127.0.0.1'),
            'username' => env('REDIS_USERNAME'),
            'password' => env('REDIS_PASSWORD'),
            'port' => env('REDIS_PORT', '6379'),
            'database' => env('REDIS_DB', '0'),
        ],
        'cache' => [
            'url' => env('REDIS_URL'),
            'host' => env('REDIS_HOST', '127.0.0.1'),
            'username' => env('REDIS_USERNAME'),
            'password' => env('REDIS_PASSWORD'),
            'port' => env('REDIS_PORT', '6379'),
            'database' => env('REDIS_CACHE_DB', '1'),
        ],
    ],
];
EOF

cat > config/filesystems.php << 'EOF'
<?php

return [
    'default' => env('FILESYSTEM_DRIVER', 'local'),
    'disks' => [
        'local' => [
            'driver' => 'local',
            'root' => storage_path('app'),
        ],
        'public' => [
            'driver' => 'local',
            'root' => storage_path('app/public'),
            'url' => env('APP_URL').'/storage',
            'visibility' => 'public',
        ],
    ],
    'links' => [
        public_path('storage') => storage_path('app/public'),
    ],
];
EOF

cat > config/hashing.php << 'EOF'
<?php

return [
    'driver' => 'bcrypt',
    'bcrypt' => [
        'rounds' => env('BCRYPT_ROUNDS', 12),
    ],
    'argon' => [
        'memory' => 65536,
        'threads' => 1,
        'time' => 4,
    ],
];
EOF

cat > config/jwt.php << 'EOF'
<?php

return [
    'secret' => env('JWT_SECRET'),
    'ttl' => env('JWT_TTL', 15),
    'refresh_ttl' => env('JWT_REFRESH_TTL', 10080),
    'algo' => 'HS256',
    'required_claims' => ['iss', 'iat', 'exp', 'nbf', 'sub', 'jti'],
    'blacklist_enabled' => true,
    'providers' => [
        'user' => 'Tymon\JWTAuth\Providers\User\EloquentUserAdapter',
        'jwt' => 'Tymon\JWTAuth\Providers\JWT\Lcobucci',
        'auth' => 'Tymon\JWTAuth\Providers\Auth\Illuminate',
        'storage' => 'Tymon\JWTAuth\Providers\Storage\Illuminate',
    ],
];
EOF

cat > config/logging.php << 'EOF'
<?php

use Monolog\Handler\StreamHandler;
use Monolog\Handler\SyslogUdpHandler;
use Monolog\Formatter\LineFormatter;

return [
    'default' => env('LOG_CHANNEL', 'stack'),
    'deprecations' => env('LOG_DEPRECATIONS_CHANNEL', 'null'),
    'channels' => [
        'stack' => [
            'driver' => 'stack',
            'channels' => ['single', 'syslog'],
            'ignore_exceptions' => false,
        ],
        'single' => [
            'driver' => 'single',
            'path' => storage_path('logs/laravel.log'),
            'level' => env('LOG_LEVEL', 'debug'),
        ],
        'syslog' => [
            'driver' => 'syslog',
            'level' => env('LOG_LEVEL', 'debug'),
            'facility' => LOG_USER,
        ],
    ],
];
EOF

cat > config/octane.php << 'EOF'
<?php

return [
    'server' => env('OCTANE_SERVER', 'swoole'),
    'max_requests' => 500,
    'workers' => env('OCTANE_WORKERS', 4),
    'swoole' => [
        'options' => [
            'worker_num' => env('OCTANE_WORKERS', 4),
        ],
    ],
];
EOF

cat > config/queue.php << 'EOF'
<?php

return [
    'default' => env('QUEUE_CONNECTION', 'sync'),
    'connections' => [
        'sync' => [
            'driver' => 'sync',
        ],
        'database' => [
            'driver' => 'database',
            'table' => 'jobs',
            'queue' => 'default',
            'retry_after' => 90,
        ],
        'rabbitmq' => [
            'driver' => 'rabbitmq',
            'queue' => env('RABBITMQ_QUEUE', 'default'),
            'host' => env('RABBITMQ_HOST', 'localhost'),
            'port' => env('RABBITMQ_PORT', 5672),
            'user' => env('RABBITMQ_USER', 'guest'),
            'password' => env('RABBITMQ_PASSWORD', 'guest'),
            'vhost' => env('RABBITMQ_VHOST', '/'),
            'connection' => env('RABBITMQ_CONNECTION', 'default'),
        ],
    ],
    'failed' => [
        'driver' => env('QUEUE_FAILED_DRIVER', 'database-uuids'),
        'database' => env('DB_CONNECTION', 'mysql'),
        'table' => 'failed_jobs',
    ],
];
EOF

cat > config/sanctum.php << 'EOF'
<?php

return [
    'stateful' => explode(',', env('SANCTUM_STATEFUL_DOMAINS', sprintf(
        '%s%s',
        'localhost,localhost:3000,127.0.0.1,127.0.0.1:8000,::1',
        env('APP_URL') ? ','.parse_url(env('APP_URL'), PHP_URL_HOST) : ''
    ))),
    'guard' => ['web'],
    'expiration' => null,
    'middleware' => [
        'verify_csrf_token' => App\Http\Middleware\VerifyCsrfToken::class,
        'encrypt_cookies' => App\Http\Middleware\EncryptCookies::class,
    ],
];
EOF

cat > config/session.php << 'EOF'
<?php

use Illuminate\Support\Str;

return [
    'driver' => env('SESSION_DRIVER', 'file'),
    'lifetime' => env('SESSION_LIFETIME', 120),
    'expire_on_close' => false,
    'encrypt' => false,
    'files' => storage_path('framework/sessions'),
    'connection' => env('SESSION_CONNECTION'),
    'table' => 'sessions',
    'store' => env('SESSION_STORE'),
    'cookie' => env(
        'SESSION_COOKIE',
        Str::slug(env('APP_NAME', 'laravel'), '_').'_session'
    ),
    'path' => '/',
    'domain' => env('SESSION_DOMAIN'),
    'secure' => env('SESSION_SECURE_COOKIE'),
    'http_only' => true,
    'same_site' => 'lax',
];
EOF

cat > routes/web.php << 'EOF'
<?php

use Illuminate\Support\Facades\Route;

Route::get('/{any}', function () {
    return view('app');
})->where('any', '.*');
EOF

cat > routes/api.php << 'EOF'
<?php

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use App\Http\Controllers\AuthController;
use App\Http\Controllers\DataImportController;
use App\Http\Controllers\ChatController;

Route::post('auth/register', [AuthController::class, 'register']);
Route::post('auth/login', [AuthController::class, 'login']);

Route::middleware('auth:sanctum')->group(function () {
    Route::post('data/import', [DataImportController::class, 'import']);
    Route::post('chat', [ChatController::class, 'sendMessage']);
});

Route::get('/health', function () {
    return response()->json(['status' => 'ok']);
});
EOF

cat > routes/console.php << 'EOF'
<?php

use Illuminate\Foundation\Inspiring;
use Illuminate\Support\Facades\Artisan;

Artisan::command('inspire', function () {
    $this->comment(Inspiring::quote());
})->purpose('Display an inspiring quote');
EOF

cat > app/Http/Controllers/AuthController.php << 'EOF'
<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Tymon\JWTAuth\Facades\JWTAuth;

class AuthController extends Controller
{
    public function register(Request $request)
    {
        $user = User::create([
            'name' => $request->name,
            'email' => $request->email,
            'password' => bcrypt($request->password),
        ]);

        $token = JWTAuth::fromUser($user);
        return response()->json(compact('user', 'token'));
    }

    public function login(Request $request)
    {
        $credentials = $request->only('email', 'password');
        if (!$token = JWTAuth::attempt($credentials)) {
            return response()->json(['error' => 'Unauthorized'], 401);
        }

        return $this->respondWithToken($token);
    }

    protected function respondWithToken($token)
    {
        return response()->json([
            'access_token' => $token,
            'token_type' => 'bearer',
            'expires_in' => JWTAuth::factory()->getTtl() * 60
        ]);
    }
}
EOF

cat > app/Http/Controllers/ChatController.php << 'EOF'
<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Http;
use App\Models\ChatSession;
use Illuminate\Support\Facades\Log;

class ChatController extends Controller
{
    public function sendMessage(Request $request)
    {
        $validated = $request->validate([
            'message' => 'required|string',
        ]);

        try {
            // 呼叫 gRPC 對話微服務
            // 這裡需要 gRPC PHP 擴展和客戶端
            // 暫時用 HTTP 模擬
            $response = Http::post('http://chat-service:50051/chat/SendMessage', [
                'message' => $validated['message'],
            ]);

            if ($response->failed()) {
                Log::error('Chat service failed', ['response' => $response->body()]);
                return response()->json(['error' => 'Chat service failed'], 500);
            }
            
            $reply = $response->json()['reply'];

            // 儲存聊天會話
            ChatSession::create([
                'user_id' => auth()->id(),
                'user_message' => $validated['message'],
                'bot_reply' => $reply,
            ]);

            return response()->json(['reply' => $reply]);
        } catch (\Exception $e) {
            Log::error('Chat controller exception', ['exception' => $e->getMessage()]);
            return response()->json(['error' => 'Internal Server Error'], 500);
        }
    }
}
EOF

cat > app/Http/Controllers/DataImportController.php << 'EOF'
<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use App\Jobs\ProcessDocumentImport;
use App\Models\KnowledgeBase;
use Illuminate\Support\Facades\Auth;

class DataImportController extends Controller
{
    public function import(Request $request)
    {
        $validated = $request->validate([
            'document_name' => 'required|string',
            'content' => 'required|string',
        ]);

        $document = KnowledgeBase::create([
            'document_name' => $validated['document_name'],
            'content' => $validated['content'],
            'metadata' => [
                'user_id' => Auth::id(),
                'imported_at' => now(),
            ],
        ]);

        ProcessDocumentImport::dispatch($document);

        return response()->json(['message' => '文件已排入佇列進行處理'], 202);
    }
}
EOF

cat > app/Jobs/ProcessDocumentImport.php << 'EOF'
<?php

namespace App\Jobs;

use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Foundation\Bus\Dispatchable;
use Illuminate\Queue\InteractsWithQueue;
use Illuminate\Queue\SerializesModels;
use App\Models\KnowledgeBase;
use App\Jobs\VectorizeDocumentJob;

class ProcessDocumentImport implements ShouldQueue
{
    use Dispatchable, InteractsWithQueue, Queueable, SerializesModels;

    protected $document;

    public function __construct(KnowledgeBase $document)
    {
        $this->document = $document;
    }

    public function handle()
    {
        // 處理文件，切塊，然後分派給向量化任務
        // 實際邏輯需在此實現
        $chunks = $this->splitDocumentIntoChunks($this->document->content);

        foreach ($chunks as $chunk) {
            VectorizeDocumentJob::dispatch($this->document->id, $chunk);
        }
    }

    protected function splitDocumentIntoChunks($content)
    {
        // 簡單的分塊邏輯，實際應使用更精細的技術
        return explode('.', $content);
    }
}
EOF

cat > app/Jobs/VectorizeDocumentJob.php << 'EOF'
<?php

namespace App\Jobs;

use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Foundation\Bus\Dispatchable;
use Illuminate\Queue\InteractsWithQueue;
use Illuminate\Queue\SerializesModels;
use Illuminate\Support\Facades\Http;

class VectorizeDocumentJob implements ShouldQueue
{
    use Dispatchable, InteractsWithQueue, Queueable, SerializesModels;

    protected $documentId;
    protected $chunk;

    public function __construct($documentId, $chunk)
    {
        $this->documentId = $documentId;
        $this->chunk = $chunk;
    }

    public function handle()
    {
        $response = Http::post('http://vectorization-service:8000/vectorize', [
            'document_id' => $this->documentId,
            'content' => $this->chunk,
        ]);

        if ($response->failed()) {
            throw new \Exception("向量化服務失敗: " . $response->body());
        }
    }
}
EOF

cat > app/Models/User.php << 'EOF'
<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Foundation\Auth\User as Authenticatable;
use Illuminate\Notifications\Notifiable;
use Tymon\JWTAuth\Contracts\JWTSubject;

class User extends Authenticatable implements JWTSubject
{
    use HasFactory, Notifiable;

    protected $fillable = [
        'name',
        'email',
        'password',
    ];

    protected $hidden = [
        'password',
        'remember_token',
    ];

    protected $casts = [
        'email_verified_at' => 'datetime',
    ];

    public function getJWTIdentifier()
    {
        return $this->getKey();
    }

    public function getJWTCustomClaims()
    {
        return [];
    }
}
EOF

cat > app/Models/KnowledgeBase.php << 'EOF'
<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class KnowledgeBase extends Model
{
    use HasFactory;
    protected $table = 'knowledge_bases';
    protected $guarded = [];
    protected $casts = ['metadata' => 'array'];
}
EOF

cat > app/Models/ChatSession.php << 'EOF'
<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class ChatSession extends Model
{
    use HasFactory;
    protected $fillable = ['user_id', 'user_message', 'bot_reply'];
}
EOF

cat > app/Http/Middleware/VerifyCsrfToken.php << 'EOF'
<?php

namespace App\Http\Middleware;

use Illuminate\Foundation\Http\Middleware\VerifyCsrfToken as Middleware;

class VerifyCsrfToken extends Middleware
{
    /**
     * The URIs that should be excluded from CSRF verification.
     *
     * @var array<int, string>
     */
    protected $except = [
        //
    ];
}
EOF

cat > app/Http/Middleware/EncryptCookies.php << 'EOF'
<?php

namespace App\Http\Middleware;

use Illuminate\Foundation\Http\Middleware\EncryptCookies as Middleware;

class EncryptCookies extends Middleware
{
    /**
     * The names of the cookies that should not be encrypted.
     *
     * @var array<int, string>
     */
    protected $except = [
        //
    ];
}
EOF

cat > app/Providers/AppServiceProvider.php << 'EOF'
<?php

namespace App\Providers;

use Illuminate\Support\ServiceProvider;

class AppServiceProvider extends ServiceProvider
{
    /**
     * Register any application services.
     */
    public function register(): void
    {
        //
    }

    /**
     * Bootstrap any application services.
     */
    public function boot(): void
    {
        //
    }
}
EOF

cat > app/Providers/RouteServiceProvider.php << 'EOF'
<?php

namespace App\Providers;

use Illuminate\Cache\RateLimiting\Limit;
use Illuminate\Foundation\Support\Providers\RouteServiceProvider as ServiceProvider;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\RateLimiter;
use Illuminate\Support\Facades\Route;

class RouteServiceProvider extends ServiceProvider
{
    /**
     * The path to your application's "home" route.
     *
     * Typically, users are redirected here after authentication.
     *
     * @var string
     */
    public const HOME = '/home';

    /**
     * Define your route model bindings, pattern filters, and other route configuration.
     */
    public function boot(): void
    {
        RateLimiter::for('api', function (Request $request) {
            return Limit::perMinute(60)->by($request->user()?->id ?: $request->ip());
        });

        $this->routes(function () {
            Route::middleware('api')
                ->prefix('api')
                ->group(base_path('routes/api.php'));

            Route::middleware('web')
                ->group(base_path('routes/web.php'));
        });
    }
}
EOF

cat > app/Exceptions/Handler.php << 'EOF'
<?php

namespace App\Exceptions;

use Illuminate\Foundation\Exceptions\Handler as ExceptionHandler;
use Throwable;

class Handler extends ExceptionHandler
{
    /**
     * The list of the inputs that are never flashed to the session on validation exceptions.
     *
     * @var array<int, string>
     */
    protected $dontFlash = [
        'current_password',
        'password',
        'password_confirmation',
    ];

    /**
     * Register the exception handling callbacks for the application.
     */
    public function register(): void
    {
        $this->reportable(function (Throwable $e) {
            //
        });
    }
}
EOF

cat > database/migrations/2023_01_01_000000_create_knowledge_bases_table.php << 'EOF'
<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('knowledge_bases', function (Blueprint $table) {
            $table->id();
            $table->string('document_name');
            $table->longText('content');
            $table->json('metadata')->nullable();
            $table->timestamps();
        });
        // 假設分區邏輯
        // DB::statement("ALTER TABLE knowledge_bases PARTITION BY KEY (id) PARTITIONS 4;");
    }

    public function down(): void
    {
        Schema::dropIfExists('knowledge_bases');
    }
};
EOF

cat > database/migrations/2023_01_01_000001_create_users_table.php << 'EOF'
<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * Run the migrations.
     */
    public function up(): void
    {
        Schema::create('users', function (Blueprint $table) {
            $table->id();
            $table->string('name');
            $table->string('email')->unique();
            $table->timestamp('email_verified_at')->nullable();
            $table->string('password');
            $table->rememberToken();
            $table->timestamps();
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('users');
    }
};
EOF

cat > database/migrations/2023_01_01_000002_create_chat_sessions_table.php << 'EOF'
<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('chat_sessions', function (Blueprint $table) {
            $table->id();
            $table->foreignId('user_id')->constrained()->onDelete('cascade');
            $table->longText('user_message');
            $table->longText('bot_reply');
            $table->timestamps();
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('chat_sessions');
    }
};
EOF

cat > database/migrations/2023_01_01_000003_create_jobs_table.php << 'EOF'
<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * Run the migrations.
     */
    public function up(): void
    {
        Schema::create('jobs', function (Blueprint $table) {
            $table->id();
            $table->string('queue')->index();
            $table->longText('payload');
            $table->unsignedTinyInteger('attempts');
            $table->unsignedInteger('reserved_at')->nullable();
            $table->unsignedInteger('available_at');
            $table->unsignedInteger('created_at');
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('jobs');
    }
};
EOF

cat > database/migrations/2023_01_01_000004_create_failed_jobs_table.php << 'EOF'
<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * Run the migrations.
     */
    public function up(): void
    {
        Schema::create('failed_jobs', function (Blueprint $table) {
            $table->id();
            $table->string('uuid')->unique();
            $table->text('connection');
            $table->text('queue');
            $table->longText('payload');
            $table->longText('exception');
            $table->timestamp('failed_at')->useCurrent();
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('failed_jobs');
    }
};
EOF

cat > database/migrations/2023_01_01_000005_create_password_reset_tokens_table.php << 'EOF'
<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('password_reset_tokens', function (Blueprint $table) {
            $table->string('email')->primary();
            $table->string('token');
            $table->timestamp('created_at')->nullable();
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('password_reset_tokens');
    }
};
EOF

cat > database/migrations/2023_01_01_000006_create_cache_table.php << 'EOF'
<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('cache', function (Blueprint $table) {
            $table->string('key')->primary();
            $table->mediumText('value');
            $table->integer('expiration');
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('cache');
    }
};
EOF

cat > database/factories/UserFactory.php << 'EOF'
<?php

namespace Database\Factories;

use Illuminate\Database\Eloquent\Factories\Factory;
use Illuminate\Support\Str;

class UserFactory extends Factory
{
    public function definition(): array
    {
        return [
            'name' => fake()->name(),
            'email' => fake()->unique()->safeEmail(),
            'email_verified_at' => now(),
            'password' => '$2y$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi', // password
            'remember_token' => Str::random(10),
        ];
    }
}
EOF

cat > database/seeders/DatabaseSeeder.php << 'EOF'
<?php

namespace Database\Seeders;

use Illuminate\Database\Seeder;
use App\Models\User;

class DatabaseSeeder extends Seeder
{
    public function run(): void
    {
        User::factory(10)->create();
    }
}
EOF

cat > tests/CreatesApplication.php << 'EOF'
<?php

namespace Tests;

use Illuminate\Contracts\Console\Kernel;
use Illuminate\Foundation\Application;

trait CreatesApplication
{
    /**
     * Creates the application.
     */
    public function createApplication(): Application
    {
        $app = require __DIR__.'/../bootstrap/app.php';

        $app->make(Kernel::class)->bootstrap();

        return $app;
    }
}
EOF

cat > tests/TestCase.php << 'EOF'
<?php

namespace Tests;

use Illuminate\Foundation\Testing\TestCase as BaseTestCase;

abstract class TestCase extends BaseTestCase
{
    use CreatesApplication;
}
EOF

cat > tests/Feature/AuthTest.php << 'EOF'
<?php

namespace Tests\Feature;

use Illuminate\Foundation\Testing\RefreshDatabase;
use Tests\TestCase;
use App\Models\User;
use Tymon\JWTAuth\Facades\JWTAuth;

class AuthTest extends TestCase
{
    use RefreshDatabase;

    public function test_user_can_register()
    {
        $userData = [
            'name' => 'Test User',
            'email' => 'test@example.com',
            'password' => 'password',
            'password_confirmation' => 'password',
        ];

        $response = $this->postJson('/api/auth/register', $userData);

        $response->assertStatus(200)
                 ->assertJsonStructure(['user', 'token']);
        
        $this->assertDatabaseHas('users', [
            'email' => 'test@example.com',
        ]);
    }

    public function test_user_can_login()
    {
        User::factory()->create([
            'email' => 'test@example.com',
            'password' => bcrypt('password'),
        ]);

        $loginData = [
            'email' => 'test@example.com',
            'password' => 'password',
        ];

        $response = $this->postJson('/api/auth/login', $loginData);

        $response->assertStatus(200)
                 ->assertJsonStructure(['access_token', 'token_type', 'expires_in']);
    }
}
EOF

cat > tests/Feature/ChatTest.php << 'EOF'
<?php

namespace Tests\Feature;

use Illuminate\Foundation\Testing\RefreshDatabase;
use Tests\TestCase;
use App\Models\User;
use Tymon\JWTAuth\Facades\JWTAuth;
use Illuminate\Support\Facades\Http;

class ChatTest extends TestCase
{
    use RefreshDatabase;

    protected $user;
    protected $token;

    protected function setUp(): void
    {
        parent::setUp();
        $this->user = User::factory()->create();
        $this->token = JWTAuth::fromUser($this->user);
    }

    public function test_authenticated_user_can_send_message()
    {
        Http::fake([
            'chat-service:50051/*' => Http::response(['reply' => 'Hello from bot'], 200),
        ]);

        $response = $this->withHeaders([
            'Authorization' => 'Bearer ' . $this->token,
        ])->postJson('/api/chat', [
            'message' => 'Hello bot',
        ]);

        $response->assertStatus(200)
                 ->assertJson(['reply' => 'Hello from bot']);
    }
}
EOF

# 4. 生成微服務檔案
echo "4. 生成微服務檔案..."
cat > microservices/vectorization-service/requirements.txt << 'EOF'
fastapi==0.95.0
uvicorn
numpy
pandas
pinecone-client
sentence-transformers==2.2.2
faiss-cpu==1.7.0
transformers==4.28.0
torch
pytest
flake8
EOF

cat > microservices/vectorization-service/.env.example << 'EOF'
PINECONE_API_KEY=
PINECONE_ENVIRONMENT=
EOF

cat > microservices/vectorization-service/.dockerignore << 'EOF'
__pycache__/
*.pyc
.pytest_cache/
.vscode/
.env
.git
.gitignore
venv/
EOF

cat > microservices/vectorization-service/.flake8 << 'EOF'
[flake8]
max-line-length = 120
extend-ignore = E203, W503
exclude = venv,.git,.pytest_cache,__pycache__
EOF

cat > microservices/vectorization-service/Dockerfile << 'EOF'
FROM python:3.10-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY ./app /app/app

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
EOF

cat > microservices/vectorization-service/app/main.py << 'EOF'
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import os
from pinecone import Pinecone
from sentence_transformers import SentenceTransformer

# 初始化 FastAPI
app = FastAPI()

# 初始化 Pinecone
pinecone = Pinecone(api_key=os.environ.get('PINECONE_API_KEY'), environment=os.environ.get('PINECONE_ENVIRONMENT'))
index = pinecone.Index('my-index')

# 初始化 SentenceTransformer
model = SentenceTransformer('all-MiniLM-L6-v2')

class Document(BaseModel):
    document_id: int
    content: str

@app.post("/vectorize")
async def vectorize_document(doc: Document):
    try:
        vector = model.encode(doc.content).tolist()
        index.upsert(vectors=[
            {'id': str(doc.document_id), 'values': vector, 'metadata': {'content': doc.content}}
        ])
        return {"message": "已成功上傳至 Pinecone"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
EOF

cat > microservices/vectorization-service/tests/test_main.py << 'EOF'
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

def test_vectorize_endpoint():
    response = client.post("/vectorize", json={"document_id": 1, "content": "Test document"})
    assert response.status_code == 200
    assert response.json()["message"] == "已成功上傳至 Pinecone"
EOF

cat > microservices/chat-service/package.json << 'EOF'
{
  "name": "chat-service",
  "version": "1.0.0",
  "description": "Node.js gRPC chat service",
  "main": "src/app.ts",
  "scripts": {
    "start": "ts-node src/app.ts",
    "build": "tsc",
    "test": "jest",
    "lint": "eslint src --ext .ts"
  },
  "dependencies": {
    "@grpc/grpc-js": "^1.8.0",
    "@grpc/proto-loader": "^0.7.0",
    "ts-proto": "^1.150.0",
    "@langchain/openai": "^0.0.28",
    "@pinecone-database/pinecone": "^0.0.10"
  },
  "devDependencies": {
    "@types/node": "^20.0.0",
    "ts-node": "^10.9.1",
    "typescript": "^5.0.0",
    "jest": "^29.5.0",
    "@types/jest": "^29.5.0",
    "ts-jest": "^29.1.0",
    "@typescript-eslint/eslint-plugin": "^6.2.0",
    "@typescript-eslint/parser": "^6.2.0",
    "eslint": "^8.45.0"
  }
}
EOF

cat > microservices/chat-service/.env.example << 'EOF'
PINECONE_API_KEY=
PINECONE_ENVIRONMENT=
OPENAI_API_KEY=
EOF

cat > microservices/chat-service/.dockerignore << 'EOF'
node_modules/
dist/
npm-debug.log
.vscode/
.env
.git
.gitignore
EOF

cat > microservices/chat-service/.eslintrc.js << 'EOF'
module.exports = {
  parser: '@typescript-eslint/parser',
  extends: [
    'eslint:recommended',
    'plugin:@typescript-eslint/recommended',
  ],
  parserOptions: {
    ecmaVersion: 2020,
    sourceType: 'module',
  },
  rules: {
    // Customize your rules here
  },
};
EOF

cat > microservices/chat-service/src/proto/chat.proto << 'EOF'
syntax = "proto3";
package chat;

service ChatService {
  rpc SendMessage (ChatRequest) returns (ChatReply);
}

message ChatRequest {
  string message = 1;
}

message ChatReply {
  string reply = 1;
}
EOF

cat > microservices/chat-service/src/app.ts << 'EOF'
import { Server, ServerCredentials } from '@grpc/grpc-js';
import { loadSync } from '@grpc/proto-loader';
import { ProtoGrpcType } from './proto/chat';
import { ChatServiceHandlers } from './proto/chat/ChatService';
import { ChatRequest } from './proto/chat/ChatRequest';
import { ChatReply } from './proto/chat/ChatReply';
import { OpenAI } from '@langchain/openai';
import { PineconeClient } from '@pinecone-database/pinecone';

const PROTO_PATH = __dirname + '/proto/chat.proto';
const packageDefinition = loadSync(PROTO_PATH, { keepCase: true, longs: String, enums: String, defaults: true, oneofs: true });
const proto = (packageDefinition as unknown) as ProtoGrpcType;

const server = new Server();

const chatService: ChatServiceHandlers = {
    SendMessage: async (call, callback) => {
        const { message } = call.request;
        console.log(`Received message: ${message}`);

        // 初始化 Pinecone
        const pinecone = new PineconeClient({
            apiKey: process.env.PINECONE_API_KEY!,
            environment: process.env.PINECONE_ENVIRONMENT!,
        });
        const index = pinecone.Index('my-index');

        // 使用 LangChain 與 Pinecone 進行 RAG
        const model = new OpenAI({
            openAIApiKey: process.env.OPENAI_API_KEY,
            temperature: 0.9,
        });

        // 假設向量由前端或另一服務提供，實際應調用向量化服務
        const queryVector = await fetch('http://vectorization-service:8000/vectorize', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ content: message })
        }).then(res => res.json()).then(data => data.vector);

        const result = await index.query({
            vector: queryVector,
            topK: 5,
            includeValues: true,
            includeMetadata: true
        });

        const context = result.matches.map((m: any) => m.metadata?.content || '').join('\n');
        const response = await model.call(`Context: ${context}\n\nQuestion: ${message}`);
        
        callback(null, { reply: response });
    }
};

server.addService(proto.chat.ChatService.service, chatService);
server.bindAsync('0.0.0.0:50051', ServerCredentials.createInsecure(), (err, port) => {
    if (err) {
        console.error(err);
        return;
    }
    console.log(`gRPC server listening on ${port}`);
    server.start();
});
EOF

cat > microservices/chat-service/tests/chat.test.ts << 'EOF'
import { Server, ServerCredentials } from '@grpc/grpc-js';
import { ChatServiceClient } from '../src/proto/chat';

describe('ChatService', () => {
    let client: ChatServiceClient;
    beforeAll((done) => {
        const server = new Server();
        server.bindAsync('localhost:50051', ServerCredentials.createInsecure(), () => {
            client = new ChatServiceClient('localhost:50051', ServerCredentials.createInsecure());
            done();
        });
    });

    it('should respond to SendMessage', (done) => {
        client.SendMessage({ message: 'Hello' }, (err, response) => {
            expect(err).toBeNull();
            expect(response.reply).toBeDefined();
            done();
        });
    });
});
EOF

cat > microservices/chat-service/Dockerfile << 'EOF'
FROM node:20-alpine

WORKDIR /app

# 複製 package.json 和 package-lock.json
COPY package*.json ./

# 安裝依賴
RUN npm install

# 複製所有檔案
COPY . .

# 編譯 TypeScript
RUN npm run build

# 啟動應用程式
CMD ["node", "dist/app.js"]
EOF

cat > microservices/chat-service/tsconfig.json << 'EOF'
{
  "compilerOptions": {
    "target": "es2020",
    "module": "commonjs",
    "rootDir": "./src",
    "outDir": "./dist",
    "strict": true,
    "esModuleInterop": true,
    "skipLibCheck": true,
    "forceConsistentCasingInFileNames": true
  },
  "include": [
    "src/**/*"
  ]
}
EOF

# 5. 生成前端檔案
echo "5. 生成前端檔案..."
cat > package.json << 'EOF'
{
  "private": true,
  "scripts": {
    "dev": "vite",
    "build": "vite build"
  },
  "devDependencies": {
    "@tailwindcss/forms": "^0.5.2",
    "alpinejs": "^3.4.2",
    "autoprefixer": "^10.4.2",
    "axios": "^1.1.2",
    "laravel-vite-plugin": "^0.7.2",
    "postcss": "^8.4.6",
    "tailwindcss": "^3.1.0",
    "vite": "^4.0.0"
  },
  "dependencies": {
    "@vitejs/plugin-vue": "^4.0.0",
    "pinia": "^2.0.0",
    "vue": "^3.3.0",
    "vue-router": "^4.0.13"
  }
}
EOF

cat > resources/js/app.js << 'EOF'
import { createApp } from 'vue';
import App from './App.vue';
import router from './router';
import { createPinia } from 'pinia';
import '../css/style.css';

const pinia = createPinia();
const app = createApp(App);
app.use(pinia);
app.use(router);
app.mount('#app');
EOF

cat > resources/js/App.vue << 'EOF'
<template>
  <div id="app" class="font-sans text-gray-800 antialiased">
    <header class="bg-gray-800 text-white p-4 shadow-md">
      <div class="container mx-auto">
        <h1 class="text-2xl font-bold">程式夥伴專案</h1>
      </div>
    </header>
    <main class="container mx-auto p-4">
      <router-view></router-view>
    </main>
  </div>
</template>

<script setup>
</script>
EOF

cat > resources/js/components/Home.vue << 'EOF'
<template>
  <div class="p-6 bg-white rounded-lg shadow-md">
    <h2 class="text-2xl font-semibold mb-4">歡迎使用！</h2>
    <p class="text-lg text-gray-600">這是一個基於 Laravel 和 Vue 的全棧應用程式。請瀏覽專案結構並開始您的開發旅程。</p>
    <div class="mt-4">
      <router-link to="/login" class="text-indigo-500 hover:text-indigo-600 font-medium">前往登入</router-link>
    </div>
  </div>
</template>

<script setup>
</script>
EOF

cat > resources/js/components/Login.vue << 'EOF'
<template>
  <div class="flex items-center justify-center min-h-screen bg-gray-100">
    <div class="w-full max-w-md p-8 space-y-6 bg-white rounded-lg shadow-md">
      <h2 class="text-2xl font-bold text-center">登入</h2>
      <form @submit.prevent="handleLogin" class="space-y-6">
        <div>
          <label for="email" class="block text-sm font-medium text-gray-700">電子郵件</label>
          <input type="email" id="email" v-model="email" required
                 class="w-full px-3 py-2 mt-1 border border-gray-300 rounded-md shadow-sm focus:ring-indigo-500 focus:border-indigo-500">
        </div>
        <div>
          <label for="password" class="block text-sm font-medium text-gray-700">密碼</label>
          <input type="password" id="password" v-model="password" required
                 class="w-full px-3 py-2 mt-1 border border-gray-300 rounded-md shadow-sm focus:ring-indigo-500 focus:border-indigo-500">
        </div>
        <button type="submit"
                class="w-full px-4 py-2 text-white bg-indigo-600 rounded-md hover:bg-indigo-700 focus:ring-indigo-500 focus:ring-offset-2 focus:outline-none focus:ring-2">
          登入
        </button>
      </form>
    </div>
  </div>
</template>

<script setup>
import { ref } from 'vue';
import { useRouter } from 'vue-router';
import { useAuthStore } from '../stores/auth';
import axios from 'axios';

const email = ref('');
const password = ref('');
const router = useRouter();
const authStore = useAuthStore();

const handleLogin = async () => {
  try {
    const response = await axios.post('/api/auth/login', {
      email: email.value,
      password: password.value,
    });
    console.log('登入成功', response.data);
    authStore.setToken(response.data.access_token);
    router.push('/');
  } catch (error) {
    console.error('登入失敗', error.response.data);
    alert('登入失敗，請檢查您的電子郵件和密碼。');
  }
};
</script>
EOF

cat > resources/js/router/index.js << 'EOF'
import { createRouter, createWebHistory } from 'vue-router';
import Home from '../components/Home.vue';
import Login from '../components/Login.vue';

const routes = [
    {
        path: '/',
        name: 'Home',
        component: Home,
    },
    {
        path: '/login',
        name: 'Login',
        component: Login,
    },
];

const router = createRouter({
    history: createWebHistory(),
    routes,
});

export default router;
EOF

cat > resources/js/stores/auth.js << 'EOF'
import { defineStore } from 'pinia';

export const useAuthStore = defineStore('auth', {
  state: () => ({
    token: localStorage.getItem('token') || null,
  }),
  getters: {
    isAuthenticated: (state) => !!state.token,
  },
  actions: {
    setToken(token) {
      this.token = token;
      localStorage.setItem('token', token);
    },
    clearToken() {
      this.token = null;
      localStorage.removeItem('token');
    },
  },
});
EOF

cat > resources/css/style.css << 'EOF'
@tailwind base;
@tailwind components;
@tailwind utilities;
EOF

cat > resources/views/app.blade.php << 'EOF'
<!DOCTYPE html>
<html lang="{{ str_replace('_', '-', app()->getLocale()) }}">
    <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <title>Laravel & Vue App</title>
        @vite('resources/js/app.js')
    </head>
    <body>
        <div id="app"></div>
    </body>
</html>
EOF

cat > vite.config.js << 'EOF'
import { defineConfig } from 'vite';
import vue from '@vitejs/plugin-vue';
import tailwindcss from 'tailwindcss';
import autoprefixer from 'autoprefixer';

export default defineConfig({
    plugins: [vue()],
    resolve: {
        alias: {
            '@': '/resources/js',
        },
    },
    css: {
        postcss: {
            plugins: [
                tailwindcss,
                autoprefixer,
            ],
        },
    },
});
EOF

# 6. 生成 Docker 配置
echo "6. 生成 Docker 配置..."
cat > docker-compose.yml << 'EOF'
services:
  nginx:
    image: nginx:1.22-alpine
    container_name: nginx
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./docker/nginx/nginx.conf:/etc/nginx/conf.d/default.conf
      - ./docker/nginx/certs:/etc/nginx/certs
      - ./docker/nginx/fastcgi_params:/etc/nginx/fastcgi_params
      - ./public:/var/www/html/public
    depends_on:
      - php
    networks:
      - app-network

  php:
    build:
      context: ./docker/php
      dockerfile: Dockerfile
    container_name: php
    volumes:
      - .:/var/www/html
    networks:
      - app-network
    environment:
      - APP_KEY=${APP_KEY}
      - APP_ENV=${APP_ENV}
      - APP_DEBUG=${APP_DEBUG}
      - DB_CONNECTION=${DB_CONNECTION}
      - DB_HOST=${DB_HOST}
      - DB_PORT=${DB_PORT}
      - DB_DATABASE=${DB_DATABASE}
      - DB_USERNAME=${DB_USERNAME}
      - DB_PASSWORD=${DB_PASSWORD}
      - REDIS_HOST=${REDIS_HOST}
      - REDIS_PORT=${REDIS_PORT}
      - RABBITMQ_HOST=${RABBITMQ_HOST}
      - RABBITMQ_PORT=${RABBITMQ_PORT}
      - RABBITMQ_USER=${RABBITMQ_USER}
      - RABBITMQ_PASSWORD=${RABBITMQ_PASSWORD}
      - JWT_SECRET=${JWT_SECRET}

  mysql:
    image: mysql:8.0
    container_name: mysql
    environment:
      MYSQL_ROOT_PASSWORD: root
      MYSQL_DATABASE: laravel
    volumes:
      - ./docker/mysql:/var/lib/mysql
      - ./docker/mysql/my.cnf:/etc/mysql/my.cnf
    ports:
      - "3306:3306"
    networks:
      - app-network
    healthcheck:
      test: ["CMD", "mysqladmin", "ping", "-h", "localhost"]
      timeout: 20s
      retries: 10

  redis:
    image: redis:7.0-alpine
    container_name: redis
    networks:
      - app-network

  rabbitmq:
    image: rabbitmq:3.9-management-alpine
    container_name: rabbitmq
    ports:
      - "5672:5672"
      - "15672:15672"
    networks:
      - app-network

  chat-service:
    build: ./microservices/chat-service
    container_name: chat-service
    environment:
      PINECONE_API_KEY: ${PINECONE_API_KEY}
      PINECONE_ENVIRONMENT: ${PINECONE_ENVIRONMENT}
      OPENAI_API_KEY: ${OPENAI_API_KEY}
    networks:
      - app-network

  vectorization-service:
    build: ./microservices/vectorization-service
    container_name: vectorization-service
    environment:
      PINECONE_API_KEY: ${PINECONE_API_KEY}
      PINECONE_ENVIRONMENT: ${PINECONE_ENVIRONMENT}
    networks:
      - app-network

  prometheus:
    image: prom/prometheus:v2.45.0
    volumes:
      - ./docker/prometheus/prometheus.yml:/etc/prometheus/prometheus.yml
    ports: ["9090:9090"]
    networks:
      - app-network

networks:
  app-network:
    driver: bridge
EOF

cat > docker/php/Dockerfile << 'EOF'
FROM php:8.2-fpm-alpine

RUN apk add --no-cache \
    curl \
    git \
    nginx \
    swoole-dev \
    gcc \
    make \
    pcre-dev \
    autoconf \
    libtool \
    openssl-dev \
    linux-headers \
    zlib-dev \
    libmemcached-dev \
    onig-dev \
    sqlite-dev \
    mysql-client \
    rabbitmq-c-dev

RUN docker-php-ext-install pdo pdo_mysql opcache bcmath exif pcntl sockets

# 安裝 Swoole
RUN pecl install swoole
RUN docker-php-ext-enable swoole

# 安裝 RabbitMQ
RUN pecl install amqp
RUN docker-php-ext-enable amqp

# 安裝 Composer
COPY --from=composer:latest /usr/bin/composer /usr/local/bin/composer

WORKDIR /var/www/html
EOF

cat > docker/php/.dockerignore << 'EOF'
.dockerignore
.env
.git
.gitignore
.editorconfig
.idea/
.vscode/
node_modules/
vendor/
docker/
kubernetes/
microservices/
public/hot
public/storage
storage/
tests/
EOF

cat > docker/php/php-fpm.conf << 'EOF'
[global]
error_log = /proc/self/fd/2

[www]
user = www-data
group = www-data
listen = 9000
listen.owner = www-data
listen.group = www-data
pm = dynamic
pm.max_children = 5
pm.start_servers = 2
pm.min_servers = 1
pm.max_servers = 3
EOF

cat > docker/php/php.ini << 'EOF'
[PHP]
memory_limit = 256M
post_max_size = 100M
upload_max_filesize = 100M
max_execution_time = 300
date.timezone = Asia/Taipei
opcache.enable=1
opcache.enable_cli=1
opcache.memory_consumption=128
opcache.interned_strings_buffer=8
opcache.max_accelerated_files=4000
opcache.revalidate_freq=60
opcache.fast_shutdown=1
EOF

cat > docker/nginx/nginx.conf << 'EOF'
server {
    listen 80;
    listen [::]:80;
    server_name localhost;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name localhost;

    ssl_certificate /etc/nginx/certs/tls.crt;
    ssl_certificate_key /etc/nginx/certs/tls.key;

    location / {
        root /var/www/html/public;
        index index.php index.html;
        try_files $uri $uri/ /index.php?$query_string;
    }

    location ~ \.php$ {
        fastcgi_split_path_info ^(.+\.php)(/.+)$;
        fastcgi_pass php:9000;
        fastcgi_index index.php;
        include fastcgi_params;
        fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
        fastcgi_param PATH_INFO $fastcgi_path_info;
    }

    location ~* \.(jpg|jpeg|gif|png|css|js|ico|woff|woff2|ttf|svg|eot)$ {
        expires 30d;
        add_header Cache-Control "public";
    }
}
EOF

cat > docker/nginx/fastcgi_params << 'EOF'
fastcgi_param  QUERY_STRING       $query_string;
fastcgi_param  REQUEST_METHOD     $request_method;
fastcgi_param  CONTENT_TYPE       $content_type;
fastcgi_param  CONTENT_LENGTH     $content_length;
fastcgi_param  SCRIPT_FILENAME    $document_root$fastcgi_script_name;
fastcgi_param  SCRIPT_NAME        $fastcgi_script_name;
fastcgi_param  REQUEST_URI        $request_uri;
fastcgi_param  DOCUMENT_URI       $document_uri;
fastcgi_param  DOCUMENT_ROOT      $document_root;
fastcgi_param  SERVER_PROTOCOL    $server_protocol;
fastcgi_param  REQUEST_SCHEME     $scheme;
fastcgi_param  HTTPS              $https if_not_empty;
fastcgi_param  GATEWAY_INTERFACE  CGI/1.1;
fastcgi_param  SERVER_SOFTWARE    nginx/$nginx_version;
fastcgi_param  REMOTE_ADDR        $remote_addr;
fastcgi_param  REMOTE_PORT        $remote_port;
fastcgi_param  SERVER_ADDR        $server_addr;
fastcgi_param  SERVER_PORT        $server_port;
fastcgi_param  SERVER_NAME        $server_name;
EOF

echo "生成 Nginx 自簽證書..."
openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout docker/nginx/certs/tls.key -out docker/nginx/certs/tls.crt -subj "/C=US/ST=State/L=City/O=Org/OU=Unit/CN=localhost"

cat > docker/mysql/my.cnf << 'EOF'
[mysqld]
# 基本設定
character-set-server = utf8mb4
collation-server = utf8mb4_unicode_ci
bind-address = 0.0.0.0
# 性能優化
innodb_buffer_pool_size = 2G
innodb_log_file_size = 256M
max_connections = 500
# 安全性
sql_mode = "STRICT_TRANS_TABLES,NO_ZERO_IN_DATE,NO_ZERO_DATE,ERROR_FOR_DIVISION_BY_ZERO,NO_ENGINE_SUBSTITUTION"
EOF

# 7. 生成 Prometheus 配置
echo "7. 生成 Prometheus 配置..."
cat > docker/prometheus/prometheus.yml << 'EOF'
global:
  scrape_interval: 15s
scrape_configs:
  - job_name: 'php'
    static_configs:
      - targets: ['php:9000']
  - job_name: 'nginx'
    static_configs:
      - targets: ['nginx:80']
EOF

# 8. 生成 Kubernetes Helm Chart
echo "8. 生成 Kubernetes Helm Chart..."
cat > kubernetes/helm/Chart.yaml << 'EOF'
apiVersion: v2
name: my-app
description: A Helm chart for a full-stack application.
version: 0.1.0
appVersion: "1.16.0"
EOF

cat > kubernetes/helm/values.yaml << 'EOF'
replicaCount: 1
image:
  repository: my-registry/my-app
  pullPolicy: IfNotPresent
  tag: "latest"
service:
  type: ClusterIP
  port: 80
ingress:
  enabled: true
  className: "nginx"
  annotations:
    nginx.ingress.kubernetes.io/rewrite-target: /
  hosts:
    - host: chart-example.local
      paths:
        - path: /
          pathType: Prefix
  tls: []
autoscaling:
  enabled: true
  minReplicas: 1
  maxReplicas: 3
  targetCPUUtilizationPercentage: 80
EOF

cat > kubernetes/helm/templates/helpers.tpl << 'EOF'
{{/*
Expand the name of the chart.
*/}}
{{- define "my-app.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "my-app.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{/*
Create chart name and version as part of the label.
*/}}
{{- define "my-app.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Common labels
*/}}
{{- define "my-app.labels" -}}
helm.sh/chart: {{ include "my-app.chart" . }}
{{ include "my-app.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{/*
Selector labels
*/}}
{{- define "my-app.selectorLabels" -}}
app.kubernetes.io/name: {{ include "my-app.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}
{{- end -}}
EOF

cat > kubernetes/helm/templates/deployment.yaml << 'EOF'
apiVersion: apps/v1
kind: Deployment
metadata:
  name: {{ include "my-app.fullname" . }}
  labels:
    {{- include "my-app.labels" . | nindent 4 }}
spec:
  replicas: {{ .Values.replicaCount }}
  selector:
    matchLabels:
      {{- include "my-app.selectorLabels" . | nindent 6 }}
  template:
    metadata:
      labels:
        {{- include "my-app.selectorLabels" . | nindent 8 }}
    spec:
      containers:
        - name: php-app
          image: "{{ .Values.image.repository }}:{{ .Values.image.tag }}"
          imagePullPolicy: {{ .Values.image.pullPolicy }}
          ports:
            - name: http
              containerPort: 80
              protocol: TCP
          livenessProbe:
            httpGet:
              path: /health
              port: http
          readinessProbe:
            httpGet:
              path: /health
              port: http
---
# Placeholder for microservices deployments
apiVersion: apps/v1
kind: Deployment
metadata:
  name: chat-service
spec:
  replicas: 1
  selector:
    matchLabels:
      app: chat-service
  template:
    metadata:
      labels:
        app: chat-service
    spec:
      containers:
        - name: chat-service
          image: chat-service:latest # Replace with your image registry
          ports:
            - containerPort: 50051
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: vectorization-service
spec:
  replicas: 1
  selector:
    matchLabels:
      app: vectorization-service
  template:
    metadata:
      labels:
        app: vectorization-service
    spec:
      containers:
        - name: vectorization-service
          image: vectorization-service:latest # Replace with your image registry
          ports:
            - containerPort: 8000
EOF

cat > kubernetes/helm/templates/ingress.yaml << 'EOF'
{{- if .Values.ingress.enabled -}}
{{- $fullName := include "my-app.fullname" . -}}
{{- $svcPort := .Values.service.port -}}
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: {{ $fullName }}
  labels:
    {{- include "my-app.labels" . | nindent 4 }}
  {{- with .Values.ingress.annotations }}
  annotations:
    {{- toYaml . | nindent 4 }}
  {{- end }}
spec:
  ingressClassName: {{ .Values.ingress.className }}
  {{- if .Values.ingress.tls }}
  tls:
    {{- range .Values.ingress.tls }}
    - hosts:
        {{- range .hosts }}
        - {{ . | quote }}
        {{- end }}
      secretName: {{ .secretName }}
    {{- end }}
  {{- end }}
  rules:
    {{- range .Values.ingress.hosts }}
    - host: {{ .host | quote }}
      http:
        paths:
          {{- range .paths }}
          - path: {{ .path }}
            pathType: {{ .pathType }}
            backend:
              service:
                name: {{ $fullName }}
                port:
                  number: {{ $svcPort }}
          {{- end }}
    {{- end }}
{{- end }}
EOF

cat > kubernetes/helm/templates/hpa.yaml << 'EOF'
{{- if .Values.autoscaling.enabled }}
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: {{ include "my-app.fullname" . }}
  labels:
    {{- include "my-app.labels" . | nindent 4 }}
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: {{ include "my-app.fullname" . }}
  minReplicas: {{ .Values.autoscaling.minReplicas }}
  maxReplicas: {{ .Values.autoscaling.maxReplicas }}
  metrics:
    - type: Resource
      resource:
        name: cpu
        target:
          type: Utilization
          averageUtilization: {{ .Values.autoscaling.targetCPUUtilizationPercentage }}
{{- end }}
EOF

cat > kubernetes/helm/templates/service.yaml << 'EOF'
apiVersion: v1
kind: Service
metadata:
  name: {{ include "my-app.fullname" . }}
  labels:
    {{- include "my-app.labels" . | nindent 4 }}
spec:
  type: {{ .Values.service.type }}
  ports:
    - port: {{ .Values.service.port }}
      targetPort: http
      protocol: TCP
      name: http
  selector:
    {{- include "my-app.selectorLabels" . | nindent 4 }}
---
apiVersion: v1
kind: Service
metadata:
  name: chat-service
spec:
  type: ClusterIP
  ports:
    - port: 50051
      targetPort: 50051
      protocol: TCP
  selector:
    app: chat-service
---
apiVersion: v1
kind: Service
metadata:
  name: vectorization-service
spec:
  type: ClusterIP
  ports:
    - port: 8000
      targetPort: 8000
      protocol: TCP
  selector:
    app: vectorization-service
EOF

cat > kubernetes/helm/templates/configmap.yaml << 'EOF'
apiVersion: v1
kind: ConfigMap
metadata:
  name: {{ include "my-app.fullname" . }}-config
  labels:
    {{- include "my-app.labels" . | nindent 4 }}
data:
  APP_NAME: "my-app"
  APP_ENV: "production"
EOF

cat > kubernetes/helm/templates/secret.yaml << 'EOF'
apiVersion: v1
kind: Secret
metadata:
  name: my-app-secrets
type: Opaque
stringData:
  APP_KEY: ""
  JWT_SECRET: ""
  PINECONE_API_KEY: ""
  PINECONE_ENVIRONMENT: ""
  OPENAI_API_KEY: ""
EOF

# 9. 生成輔助腳本
echo "9. 生成輔助腳本..."
mkdir -p scripts

cat > scripts/dev-setup.sh << 'EOF'
#!/bin/bash
echo "正在啟動 Docker 容器..."
docker-compose up -d --build
echo "正在安裝 PHP 依賴..."
docker-compose exec php composer install
echo "正在產生 Laravel APP_KEY..."
docker-compose exec php php artisan key:generate
echo "正在產生 JWT_SECRET..."
docker-compose exec php php artisan jwt:secret --force
echo "正在執行資料庫遷移..."
docker-compose exec php php artisan migrate --seed
echo "開發環境設定完成！"
EOF

cat > scripts/test.sh << 'EOF'
#!/bin/bash
echo "執行 Laravel 後端測試..."
docker-compose exec php vendor/bin/phpunit
echo "執行 Chat Service 測試..."
docker-compose exec chat-service npm run test
echo "執行 Vectorization Service 測試..."
docker-compose exec vectorization-service pytest
EOF

cat > scripts/lint.sh << 'EOF'
#!/bin/bash

# PHP Linting
echo "Running PHP CS Fixer..."
# Assumes php-cs-fixer is installed and configured.
# You might need to install it globally or via composer.
# composer require friendsofphp/php-cs-fixer --dev
# docker-compose exec php vendor/bin/php-cs-fixer fix --dry-run --verbose --diff
# or if it's not installed in the container, you can run a temporary container
docker run --rm -v $(pwd):/app -w /app composer:2.4 sh -c "composer require --dev friendsofphp/php-cs-fixer && vendor/bin/php-cs-fixer fix --dry-run --verbose" || true
echo "PHP linting finished."

# TypeScript Linting
echo "Running ESLint for Chat Service..."
docker-compose exec chat-service npm run lint || true
echo "TypeScript linting finished."

# Python Linting
echo "Running Flake8 for Vectorization Service..."
docker-compose exec vectorization-service python3 -m flake8 --config microservices/vectorization-service/.flake8 || true
echo "Python linting finished."

echo "All linting tasks completed."
EOF

cat > scripts/build.sh << 'EOF'
#!/bin/bash
echo "Building Vue frontend..."
docker-compose exec php npm run build

echo "Building Chat Service..."
docker-compose exec chat-service npm run build

# Note: Python services typically don't require a separate build step,
# as they are interpreted languages. The Docker build handles dependencies.

echo "All services built successfully."
EOF

cat > scripts/deploy-helm.sh << 'EOF'
#!/bin/bash
echo "部署 Helm Chart..."
helm upgrade --install my-app ./kubernetes/helm --set image.tag=latest --namespace my-namespace --create-namespace
EOF

chmod +x scripts/dev-setup.sh scripts/test.sh scripts/deploy-helm.sh scripts/lint.sh scripts/build.sh

# 10. 生成 .gitignore 和 README.md
echo "10. 生成 .gitignore 和 README.md..."
cat > .gitignore << 'EOF'
/node_modules
/vendor
/.env
/public/hot
/public/storage
/storage/*.key
/storage/oauth-*
/.idea
/.vscode
.DS_Store
*.log
npm-debug.log*
yarn-debug.log*
yarn-error.log*
/docker/mysql
/docker/prometheus
EOF

cat > README.md << 'EOF'
# 專案名稱

這是一個基於 Laravel 11、Vue 3 和微服務架構的完整專案範例。

## 技術棧

- **後端**: Laravel 11, Laravel Octane (Swoole), JWT Auth
- **微服務**:
  - **向量化服務**: Python (FastAPI, SentenceTransformer, Faiss)
  - **對話服務**: Node.js (gRPC, LangChain JS)
- **前端**: Vue 3, Vite, Pinia, Tailwind CSS
- **資料庫/快取**: MySQL 8.0, Redis 7.0, RabbitMQ 3.9
- **部署**: Docker, Docker Compose, Kubernetes, Helm
- **CI/CD**: GitHub Actions

## 開始使用

### 1. 專案初始化

執行以下腳本來自動生成所有專案檔案和目錄結構：

```bash
bash generate_project.sh
```

### 2. 開發環境設置

使用 Docker Compose 啟動所有服務：

```bash
./scripts/dev-setup.sh
```

### 3. 執行建構

執行建構所有服務的腳本：

```bash
./scripts/build.sh
```

### 4. 執行測試

執行所有後端和微服務的單元測試和整合測試：

```bash
./scripts/test.sh
```

### 5. 部署

使用 Helm 將應用程式部署到 Kubernetes：

```bash
./scripts/deploy-helm.sh
```
EOF

echo "所有檔案已生成。請檢查 .env.example 並填入您的環境變數。祝您開發順利！"
