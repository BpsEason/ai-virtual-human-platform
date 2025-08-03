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
