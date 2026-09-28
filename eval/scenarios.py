"""Comprehensive benchmark suite with 10 production incident scenarios.

Categories:
1. Deploy-Caused Errors (Code regressions, faulty migrations, unhandled exceptions)
2. Resource Exhaustion (JVM Heap OOM, DB Connection Pool Starvation, CPU/Thread Saturation)
3. Red Herrings (Recent deploy is benign; true cause is upstream vendor, expired TLS cert, or DB deadlock)
"""

SCENARIOS = [
    # =========================================================================
    # Category 1: Deploy-Caused Errors (4 Scenarios)
    # =========================================================================
    {
        "id": "scenario_01_checkout_npe_regression",
        "name": "Checkout Service NullPointerException Post-Deploy Regression",
        "service": "checkout-service",
        "category": "deploy_regression",
        "description": "Deployment v2.4.0 introduced unhandled NullPointerException in PaymentMethodValidator.java:142 when parsing digital wallet payloads.",
        "telemetry": {
            "logs": [
                {
                    "timestamp": "2026-09-01T10:14:30.000Z",
                    "level": "INFO",
                    "service": "checkout-service",
                    "logger": "c.e.c.CheckoutApplication",
                    "message": "Deployment completed for version v2.4.0. Container started.",
                    "stack_trace": None,
                },
                {
                    "timestamp": "2026-09-01T10:15:22.104Z",
                    "level": "ERROR",
                    "service": "checkout-service",
                    "logger": "c.e.c.PaymentProcessor",
                    "message": "Payment validation failed for order 884129: null pointer encountered",
                    "stack_trace": 'java.lang.NullPointerException: Cannot invoke "com.ecommerce.checkout.model.PaymentMethod.getToken()" because "method" is null\n\tat com.ecommerce.checkout.validator.PaymentMethodValidator.validate(PaymentMethodValidator.java:142)\n\tat com.ecommerce.checkout.service.CheckoutProcessor.processOrder(CheckoutProcessor.java:78)',
                },
                {
                    "timestamp": "2026-09-01T10:15:45.312Z",
                    "level": "ERROR",
                    "service": "checkout-service",
                    "logger": "c.e.c.PaymentProcessor",
                    "message": "Payment validation failed for order 884130: null pointer encountered",
                    "stack_trace": 'java.lang.NullPointerException: Cannot invoke "com.ecommerce.checkout.model.PaymentMethod.getToken()" because "method" is null\n\tat com.ecommerce.checkout.validator.PaymentMethodValidator.validate(PaymentMethodValidator.java:142)\n\tat com.ecommerce.checkout.service.CheckoutProcessor.processOrder(CheckoutProcessor.java:78)',
                },
                {
                    "timestamp": "2026-09-01T10:16:10.881Z",
                    "level": "ERROR",
                    "service": "checkout-service",
                    "logger": "c.e.c.PaymentProcessor",
                    "message": "Payment validation failed for order 884135",
                    "stack_trace": 'java.lang.NullPointerException: Cannot invoke "com.ecommerce.checkout.model.PaymentMethod.getToken()" because "method" is null\n\tat com.ecommerce.checkout.validator.PaymentMethodValidator.validate(PaymentMethodValidator.java:142)\n\tat com.ecommerce.checkout.service.CheckoutProcessor.processOrder(CheckoutProcessor.java:78)',
                },
            ],
            "deployments": [
                {
                    "id": "dep-checkout-240",
                    "service": "checkout-service",
                    "version": "v2.4.0",
                    "previous_version": "v2.3.9",
                    "timestamp": "2026-09-01T10:14:00Z",
                    "commit_hash": "a9f4c3b",
                    "author": "alice@company.com",
                    "commit_message": "feat: add digital wallet checkout support and payment method validation",
                    "rollback_version": "v2.3.9",
                    "changes": [
                        "PaymentMethodValidator.java: Added digital wallet validation",
                        "CheckoutProcessor.java: Integrated validation chain",
                    ],
                }
            ],
            "anomalies": [
                {
                    "metric_name": "error_rate_5xx_pct",
                    "onset_timestamp": "2026-09-01T10:15:00Z",
                    "peak_value": 52.3,
                    "baseline_mean": 0.02,
                    "summary": "error_rate_5xx_pct spiked from 0.02 to 52.30% starting at 2026-09-01T10:15:00Z",
                },
                {
                    "metric_name": "p99_latency_ms",
                    "onset_timestamp": "2026-09-01T10:15:00Z",
                    "peak_value": 4350.0,
                    "baseline_mean": 110.0,
                    "summary": "p99_latency_ms spiked from 110.00 to 4350.00ms starting at 2026-09-01T10:15:00Z",
                },
            ],
        },
        "expected": {
            "cause_category": "deploy_regression",
            "is_deploy_cause": True,
            "culprit_commit": "a9f4c3b",
            "culprit_version": "v2.4.0",
            "exception_substring": "NullPointerException",
            "faulty_file_and_line": "PaymentMethodValidator.java:142",
            "action_type": "ROLLBACK_DEPLOYMENT",
            "target_rollback_version": "v2.3.9",
            "min_confidence": 0.85,
            "evidence_keywords": ["a9f4c3b", "PaymentMethodValidator.java:142", "NullPointerException", "v2.4.0"],
        },
    },
    {
        "id": "scenario_02_auth_jwt_key_mismatch",
        "name": "Auth Service JWT Signature Verification Key Mismatch",
        "service": "auth-service",
        "category": "deploy_regression",
        "description": "Deployment v1.8.3 modified token signing algorithm in JwtTokenProvider.py:88, throwing SignatureVerificationError on all active user tokens.",
        "telemetry": {
            "logs": [
                {
                    "timestamp": "2026-09-01T11:00:15.000Z",
                    "level": "INFO",
                    "service": "auth-service",
                    "logger": "auth.server",
                    "message": "Auth service v1.8.3 rolling release live.",
                    "stack_trace": None,
                },
                {
                    "timestamp": "2026-09-01T11:01:05.120Z",
                    "level": "ERROR",
                    "service": "auth-service",
                    "logger": "auth.jwt",
                    "message": "Failed to verify JWT bearer token for user 90214",
                    "stack_trace": 'jwt.exceptions.SignatureVerificationError: Signature verification failed (expected ES256, received RS256)\n  File "JwtTokenProvider.py", line 88, in verify_token\n    return jwt.decode(token, self.public_key, algorithms=["ES256"])\n  File "AuthMiddleware.py", line 42, in authenticate_request',
                },
                {
                    "timestamp": "2026-09-01T11:01:22.450Z",
                    "level": "ERROR",
                    "service": "auth-service",
                    "logger": "auth.jwt",
                    "message": "Failed to verify JWT bearer token for user 90215",
                    "stack_trace": 'jwt.exceptions.SignatureVerificationError: Signature verification failed (expected ES256, received RS256)\n  File "JwtTokenProvider.py", line 88, in verify_token\n    return jwt.decode(token, self.public_key, algorithms=["ES256"])\n  File "AuthMiddleware.py", line 42, in authenticate_request',
                },
            ],
            "deployments": [
                {
                    "id": "dep-auth-183",
                    "service": "auth-service",
                    "version": "v1.8.3",
                    "previous_version": "v1.8.2",
                    "timestamp": "2026-09-01T11:00:00Z",
                    "commit_hash": "b4f81c2",
                    "author": "charlie@company.com",
                    "commit_message": "feat: enforce ES256 asymmetric token verification",
                    "rollback_version": "v1.8.2",
                    "changes": [
                        "JwtTokenProvider.py: Update algorithm decoding to ES256",
                    ],
                }
            ],
            "anomalies": [
                {
                    "metric_name": "error_rate_5xx_pct",
                    "onset_timestamp": "2026-09-01T11:01:00Z",
                    "peak_value": 78.4,
                    "baseline_mean": 0.01,
                    "summary": "error_rate_5xx_pct spiked to 78.40% starting at 2026-09-01T11:01:00Z",
                }
            ],
        },
        "expected": {
            "cause_category": "deploy_regression",
            "is_deploy_cause": True,
            "culprit_commit": "b4f81c2",
            "culprit_version": "v1.8.3",
            "exception_substring": "SignatureVerificationError",
            "faulty_file_and_line": "JwtTokenProvider.py:88",
            "action_type": "ROLLBACK_DEPLOYMENT",
            "target_rollback_version": "v1.8.2",
            "min_confidence": 0.85,
            "evidence_keywords": ["b4f81c2", "JwtTokenProvider.py:88", "SignatureVerificationError", "v1.8.3"],
        },
    },
    {
        "id": "scenario_03_inventory_missing_column_migration",
        "name": "Inventory Service DB Schema Column Missing Regression",
        "service": "inventory-service",
        "category": "deploy_regression",
        "description": "Deployment v3.1.0 updated SQL query to select warehouse_zone before migration applied, causing DatabaseSyntaxError in InventoryRepository.go:64.",
        "telemetry": {
            "logs": [
                {
                    "timestamp": "2026-09-01T09:30:10.000Z",
                    "level": "INFO",
                    "service": "inventory-service",
                    "logger": "inventory.main",
                    "message": "Inventory service v3.1.0 deployed and listening on port 8080.",
                    "stack_trace": None,
                },
                {
                    "timestamp": "2026-09-01T09:31:02.341Z",
                    "level": "ERROR",
                    "service": "inventory-service",
                    "logger": "inventory.db",
                    "message": "Query execution failed on inventory_items table",
                    "stack_trace": 'pq: column "warehouse_zone" does not exist\n\tat InventoryRepository.go:64\n\tat StockService.go:112\n\tat InventoryHandler.go:45',
                },
                {
                    "timestamp": "2026-09-01T09:31:15.910Z",
                    "level": "ERROR",
                    "service": "inventory-service",
                    "logger": "inventory.db",
                    "message": "Query execution failed on inventory_items table",
                    "stack_trace": 'pq: column "warehouse_zone" does not exist\n\tat InventoryRepository.go:64\n\tat StockService.go:112\n\tat InventoryHandler.go:45',
                },
            ],
            "deployments": [
                {
                    "id": "dep-inv-310",
                    "service": "inventory-service",
                    "version": "v3.1.0",
                    "previous_version": "v3.0.9",
                    "timestamp": "2026-09-01T09:30:00Z",
                    "commit_hash": "f8a201c",
                    "author": "dan@company.com",
                    "commit_message": "feat: add warehouse zone partitioning to inventory queries",
                    "rollback_version": "v3.0.9",
                    "changes": [
                        "InventoryRepository.go: query warehouse_zone field",
                    ],
                }
            ],
            "anomalies": [
                {
                    "metric_name": "error_rate_5xx_pct",
                    "onset_timestamp": "2026-09-01T09:31:00Z",
                    "peak_value": 64.1,
                    "baseline_mean": 0.05,
                    "summary": "error_rate_5xx_pct spiked to 64.10% starting at 2026-09-01T09:31:00Z",
                }
            ],
        },
        "expected": {
            "cause_category": "deploy_regression",
            "is_deploy_cause": True,
            "culprit_commit": "f8a201c",
            "culprit_version": "v3.1.0",
            "exception_substring": "warehouse_zone",
            "faulty_file_and_line": "InventoryRepository.go:64",
            "action_type": "ROLLBACK_DEPLOYMENT",
            "target_rollback_version": "v3.0.9",
            "min_confidence": 0.85,
            "evidence_keywords": ["f8a201c", "InventoryRepository.go:64", "warehouse_zone", "v3.1.0"],
        },
    },
    {
        "id": "scenario_04_notification_template_typeerror",
        "name": "Notification Service Template Parsing TypeError Panic",
        "service": "notification-service",
        "category": "deploy_regression",
        "description": "Deployment v1.2.5 omitted null check on user metadata in TemplateEngine.ts:105, throwing TypeError on email template dispatch.",
        "telemetry": {
            "logs": [
                {
                    "timestamp": "2026-09-01T12:00:20.000Z",
                    "level": "INFO",
                    "service": "notification-service",
                    "logger": "notif.worker",
                    "message": "Notification worker v1.2.5 online.",
                    "stack_trace": None,
                },
                {
                    "timestamp": "2026-09-01T12:01:45.602Z",
                    "level": "ERROR",
                    "service": "notification-service",
                    "logger": "notif.render",
                    "message": "Unhandled exception while rendering email template id 402",
                    "stack_trace": "TypeError: Cannot read properties of undefined (reading 'recipient_email')\n    at TemplateEngine.ts:105:24\n    at async NotificationDispatcher.ts:80:12",
                },
                {
                    "timestamp": "2026-09-01T12:02:10.114Z",
                    "level": "ERROR",
                    "service": "notification-service",
                    "logger": "notif.render",
                    "message": "Unhandled exception while rendering email template id 403",
                    "stack_trace": "TypeError: Cannot read properties of undefined (reading 'recipient_email')\n    at TemplateEngine.ts:105:24\n    at async NotificationDispatcher.ts:80:12",
                },
            ],
            "deployments": [
                {
                    "id": "dep-notif-125",
                    "service": "notification-service",
                    "version": "v1.2.5",
                    "previous_version": "v1.2.4",
                    "timestamp": "2026-09-01T12:00:00Z",
                    "commit_hash": "d1c94e7",
                    "author": "eve@company.com",
                    "commit_message": "feat: dynamic recipient email substitution",
                    "rollback_version": "v1.2.4",
                    "changes": [
                        "TemplateEngine.ts: parse recipient metadata directly",
                    ],
                }
            ],
            "anomalies": [
                {
                    "metric_name": "error_rate_5xx_pct",
                    "onset_timestamp": "2026-09-01T12:01:00Z",
                    "peak_value": 45.0,
                    "baseline_mean": 0.00,
                    "summary": "error_rate_5xx_pct spiked to 45.00% starting at 2026-09-01T12:01:00Z",
                }
            ],
        },
        "expected": {
            "cause_category": "deploy_regression",
            "is_deploy_cause": True,
            "culprit_commit": "d1c94e7",
            "culprit_version": "v1.2.5",
            "exception_substring": "TypeError",
            "faulty_file_and_line": "TemplateEngine.ts:105",
            "action_type": "ROLLBACK_DEPLOYMENT",
            "target_rollback_version": "v1.2.4",
            "min_confidence": 0.85,
            "evidence_keywords": ["d1c94e7", "TemplateEngine.ts:105", "TypeError", "v1.2.5"],
        },
    },

    # =========================================================================
    # Category 2: Resource Exhaustion (3 Scenarios)
    # =========================================================================
    {
        "id": "scenario_05_analytics_jvm_heap_oom",
        "name": "Analytics Service JVM Heap Space OutOfMemoryError",
        "service": "analytics-service",
        "category": "resource_exhaustion",
        "description": "Unbounded batch accumulation under high event volume exhausted JVM heap (98.5% memory), throwing java.lang.OutOfMemoryError. Last deploy was 4 days ago.",
        "telemetry": {
            "logs": [
                {
                    "timestamp": "2026-09-01T08:15:10.000Z",
                    "level": "WARN",
                    "service": "analytics-service",
                    "logger": "analytics.gc",
                    "message": "GC pause time exceeded threshold: 2450ms (PS MarkSweep)",
                    "stack_trace": None,
                },
                {
                    "timestamp": "2026-09-01T08:16:30.812Z",
                    "level": "ERROR",
                    "service": "analytics-service",
                    "logger": "analytics.aggregator",
                    "message": "Critical failure in BatchAggregator background worker",
                    "stack_trace": "java.lang.OutOfMemoryError: Java heap space\n\tat BatchAggregator.java:210\n\tat EventBufferPool.java:94\n\tat AnalyticsStreamConsumer.java:155",
                },
                {
                    "timestamp": "2026-09-01T08:17:00.120Z",
                    "level": "ERROR",
                    "service": "analytics-service",
                    "logger": "analytics.aggregator",
                    "message": "Unable to allocate new byte array for incoming event stream",
                    "stack_trace": "java.lang.OutOfMemoryError: Java heap space\n\tat BatchAggregator.java:210",
                },
            ],
            "deployments": [
                {
                    "id": "dep-analytics-090",
                    "service": "analytics-service",
                    "version": "v0.9.0",
                    "previous_version": "v0.8.9",
                    "timestamp": "2026-08-28T14:00:00Z",
                    "commit_hash": "33a90f1",
                    "author": "frank@company.com",
                    "commit_message": "chore: bump spark streaming dependency",
                    "rollback_version": "v0.8.9",
                    "changes": ["pom.xml: bump version"],
                }
            ],
            "anomalies": [
                {
                    "metric_name": "memory_utilization_pct",
                    "onset_timestamp": "2026-09-01T08:15:00Z",
                    "peak_value": 98.5,
                    "baseline_mean": 42.0,
                    "summary": "memory_utilization_pct spiked from 42.00 to 98.50% starting at 2026-09-01T08:15:00Z",
                },
                {
                    "metric_name": "error_rate_5xx_pct",
                    "onset_timestamp": "2026-09-01T08:16:00Z",
                    "peak_value": 41.2,
                    "baseline_mean": 0.01,
                    "summary": "error_rate_5xx_pct spiked to 41.20% starting at 2026-09-01T08:16:00Z",
                },
            ],
        },
        "expected": {
            "cause_category": "resource_exhaustion",
            "is_deploy_cause": False,
            "culprit_commit": None,
            "culprit_version": None,
            "exception_substring": "OutOfMemoryError",
            "faulty_file_and_line": "BatchAggregator.java:210",
            "action_type": "SCALE_UP",
            "min_confidence": 0.85,
            "evidence_keywords": ["OutOfMemoryError", "Java heap space", "memory_utilization_pct", "98.5"],
        },
    },
    {
        "id": "scenario_06_order_db_connection_pool_exhaustion",
        "name": "Order Service HikariCP Database Connection Pool Exhaustion",
        "service": "order-service",
        "category": "resource_exhaustion",
        "description": "Flash sale flash-traffic saturated all 50 database pool connections, throwing HikariPool ConnectionTimeoutException. No deploy in 48 hours.",
        "telemetry": {
            "logs": [
                {
                    "timestamp": "2026-09-01T13:40:00.000Z",
                    "level": "WARN",
                    "service": "order-service",
                    "logger": "com.zaxxer.hikari.HikariPool",
                    "message": "HikariPool-1 - Connection pool utilization reached 100% (50/50 active, 120 waiting)",
                    "stack_trace": None,
                },
                {
                    "timestamp": "2026-09-01T13:41:12.550Z",
                    "level": "ERROR",
                    "service": "order-service",
                    "logger": "order.dao.OrderDAO",
                    "message": "Failed to acquire JDBC connection for placing order 77102",
                    "stack_trace": "java.sql.SQLTransientConnectionException: HikariPool-1 - Connection is not available, request timed out after 30000ms\n\tat com.zaxxer.hikari.pool.HikariPool.getConnection(HikariPool.java:217)\n\tat OrderDAO.java:53\n\tat OrderService.java:180",
                },
                {
                    "timestamp": "2026-09-01T13:41:45.890Z",
                    "level": "ERROR",
                    "service": "order-service",
                    "logger": "order.dao.OrderDAO",
                    "message": "Failed to acquire JDBC connection for placing order 77105",
                    "stack_trace": "java.sql.SQLTransientConnectionException: HikariPool-1 - Connection is not available, request timed out after 30000ms\n\tat com.zaxxer.hikari.pool.HikariPool.getConnection(HikariPool.java:217)\n\tat OrderDAO.java:53",
                },
            ],
            "deployments": [
                {
                    "id": "dep-order-210",
                    "service": "order-service",
                    "version": "v2.1.0",
                    "previous_version": "v2.0.9",
                    "timestamp": "2026-08-30T10:00:00Z",
                    "commit_hash": "77e411b",
                    "author": "grace@company.com",
                    "commit_message": "chore: dependency upgrades",
                    "rollback_version": "v2.0.9",
                    "changes": ["build.gradle: bump versions"],
                }
            ],
            "anomalies": [
                {
                    "metric_name": "p99_latency_ms",
                    "onset_timestamp": "2026-09-01T13:40:00Z",
                    "peak_value": 31500.0,
                    "baseline_mean": 95.0,
                    "summary": "p99_latency_ms spiked from 95.00 to 31500.00ms starting at 2026-09-01T13:40:00Z",
                },
                {
                    "metric_name": "error_rate_5xx_pct",
                    "onset_timestamp": "2026-09-01T13:41:00Z",
                    "peak_value": 38.6,
                    "baseline_mean": 0.02,
                    "summary": "error_rate_5xx_pct spiked to 38.60% starting at 2026-09-01T13:41:00Z",
                },
            ],
        },
        "expected": {
            "cause_category": "resource_exhaustion",
            "is_deploy_cause": False,
            "culprit_commit": None,
            "culprit_version": None,
            "exception_substring": "HikariPool",
            "faulty_file_and_line": "OrderDAO.java:53",
            "action_type": "SCALE_UP",
            "min_confidence": 0.85,
            "evidence_keywords": ["HikariPool", "Connection is not available", "p99_latency_ms"],
        },
    },
    {
        "id": "scenario_07_search_cpu_thread_starvation",
        "name": "Search Service CPU Saturation and ThreadPoolExecutor Starvation",
        "service": "search-service",
        "category": "resource_exhaustion",
        "description": "Unindexed complex regex queries spiked CPU to 99.4%, saturating worker threads and causing RejectedExecutionException. No deploy in 72 hours.",
        "telemetry": {
            "logs": [
                {
                    "timestamp": "2026-09-01T15:10:00.000Z",
                    "level": "WARN",
                    "service": "search-service",
                    "logger": "search.metrics",
                    "message": "CPU threshold exceeded: 99.4% on search-worker pod cluster",
                    "stack_trace": None,
                },
                {
                    "timestamp": "2026-09-01T15:11:15.300Z",
                    "level": "ERROR",
                    "service": "search-service",
                    "logger": "search.worker",
                    "message": "Worker thread pool task submission rejected",
                    "stack_trace": "concurrent.futures.RejectedExecutionException: ThreadPoolExecutor queue limit 500 exceeded, pool size 64 saturated\n  File SearchWorker.py, line 140, in submit_query\n  File SearchController.py, line 55, in handle_search",
                },
                {
                    "timestamp": "2026-09-01T15:11:40.710Z",
                    "level": "ERROR",
                    "service": "search-service",
                    "logger": "search.worker",
                    "message": "Worker thread pool task submission rejected",
                    "stack_trace": "concurrent.futures.RejectedExecutionException: ThreadPoolExecutor queue limit 500 exceeded, pool size 64 saturated\n  File SearchWorker.py, line 140, in submit_query",
                },
            ],
            "deployments": [
                {
                    "id": "dep-search-401",
                    "service": "search-service",
                    "version": "v4.0.1",
                    "previous_version": "v4.0.0",
                    "timestamp": "2026-08-29T11:30:00Z",
                    "commit_hash": "55c82aa",
                    "author": "harry@company.com",
                    "commit_message": "chore: update documentation",
                    "rollback_version": "v4.0.0",
                    "changes": ["README.md: update setup docs"],
                }
            ],
            "anomalies": [
                {
                    "metric_name": "cpu_utilization_pct",
                    "onset_timestamp": "2026-09-01T15:10:00Z",
                    "peak_value": 99.4,
                    "baseline_mean": 28.0,
                    "summary": "cpu_utilization_pct spiked from 28.00 to 99.40% starting at 2026-09-01T15:10:00Z",
                },
                {
                    "metric_name": "error_rate_5xx_pct",
                    "onset_timestamp": "2026-09-01T15:11:00Z",
                    "peak_value": 31.5,
                    "baseline_mean": 0.00,
                    "summary": "error_rate_5xx_pct spiked to 31.50% starting at 2026-09-01T15:11:00Z",
                },
            ],
        },
        "expected": {
            "cause_category": "resource_exhaustion",
            "is_deploy_cause": False,
            "culprit_commit": None,
            "culprit_version": None,
            "exception_substring": "RejectedExecutionException",
            "faulty_file_and_line": "SearchWorker.py:140",
            "action_type": "THROTTLE_TRAFFIC",
            "min_confidence": 0.85,
            "evidence_keywords": ["RejectedExecutionException", "ThreadPoolExecutor", "cpu_utilization_pct", "99.4"],
        },
    },

    # =========================================================================
    # Category 3: Red Herrings (Deploy is NOT the Cause - 3 Scenarios)
    # =========================================================================
    {
        "id": "scenario_08_payment_stripe_upstream_outage_red_herring",
        "name": "Payment Gateway 3rd-Party Stripe Global Outage Red Herring",
        "service": "payment-gateway",
        "category": "red_herring",
        "description": "Benign deploy v1.5.2 (logging & comments) occurred 15 min ago. Stripe API went down globally with 503 Service Unavailable. Deploy is NOT the cause.",
        "telemetry": {
            "logs": [
                {
                    "timestamp": "2026-09-01T10:00:00.000Z",
                    "level": "INFO",
                    "service": "payment-gateway",
                    "logger": "payment.main",
                    "message": "Payment gateway v1.5.2 started successfully.",
                    "stack_trace": None,
                },
                {
                    "timestamp": "2026-09-01T10:15:12.110Z",
                    "level": "ERROR",
                    "service": "payment-gateway",
                    "logger": "payment.stripe.client",
                    "message": "External API call to api.stripe.com failed with HTTP 503",
                    "stack_trace": "com.stripe.exception.StripeException: 503 Service Unavailable - Upstream cloud infrastructure gateway timeout at api.stripe.com\n\tat StripeClient.java:94\n\tat StripePaymentGateway.java:144\n\tat PaymentController.java:82",
                },
                {
                    "timestamp": "2026-09-01T10:15:35.450Z",
                    "level": "ERROR",
                    "service": "payment-gateway",
                    "logger": "payment.stripe.client",
                    "message": "External API call to api.stripe.com failed with HTTP 503",
                    "stack_trace": "com.stripe.exception.StripeException: 503 Service Unavailable - Upstream cloud infrastructure gateway timeout at api.stripe.com\n\tat StripeClient.java:94\n\tat StripePaymentGateway.java:144",
                },
            ],
            "deployments": [
                {
                    "id": "dep-payment-152",
                    "service": "payment-gateway",
                    "version": "v1.5.2",
                    "previous_version": "v1.5.1",
                    "timestamp": "2026-09-01T10:00:00Z",
                    "commit_hash": "e3d119a",
                    "author": "bob@company.com",
                    "commit_message": "docs: update API documentation and comments",
                    "rollback_version": "v1.5.1",
                    "changes": ["README.md: update doc", "Config.java: add comment"],
                }
            ],
            "anomalies": [
                {
                    "metric_name": "error_rate_5xx_pct",
                    "onset_timestamp": "2026-09-01T10:15:00Z",
                    "peak_value": 72.0,
                    "baseline_mean": 0.01,
                    "summary": "error_rate_5xx_pct spiked to 72.00% starting at 2026-09-01T10:15:00Z",
                }
            ],
        },
        "expected": {
            "cause_category": "red_herring",
            "is_deploy_cause": False,
            "culprit_commit": None,
            "culprit_version": None,
            "exception_substring": "503 Service Unavailable",
            "faulty_file_and_line": "StripeClient.java:94",
            "action_type": "MANUAL_INVESTIGATION",
            "min_confidence": 0.85,
            "evidence_keywords": ["Stripe", "503 Service Unavailable", "upstream", "benign"],
        },
    },
    {
        "id": "scenario_09_user_service_expired_tls_cert_red_herring",
        "name": "User Service Expired TLS/SSL Certificate Red Herring",
        "service": "user-service",
        "category": "red_herring",
        "description": "Benign deploy v2.0.1 (README cleanup) deployed 25 min ago. Cluster mTLS certificate expired at 11:00 UTC, causing SSLHandshakeException. Deploy is NOT the cause.",
        "telemetry": {
            "logs": [
                {
                    "timestamp": "2026-09-01T10:35:00.000Z",
                    "level": "INFO",
                    "service": "user-service",
                    "logger": "user.server",
                    "message": "User service v2.0.1 running smoothly.",
                    "stack_trace": None,
                },
                {
                    "timestamp": "2026-09-01T11:00:04.102Z",
                    "level": "ERROR",
                    "service": "user-service",
                    "logger": "user.security",
                    "message": "TLS Handshake negotiation failed on inbound internal RPC connection",
                    "stack_trace": "javax.net.ssl.SSLHandshakeException: PKIX path validation failed: certificate expired on 2026-09-01T11:00:00Z\n\tat sun.security.ssl.Alert.createSSLException(Alert.java:131)\n\tat SecurityContext.java:112\n\tat GrpcServerInterceptor.java:65",
                },
                {
                    "timestamp": "2026-09-01T11:00:25.801Z",
                    "level": "ERROR",
                    "service": "user-service",
                    "logger": "user.security",
                    "message": "TLS Handshake negotiation failed on inbound internal RPC connection",
                    "stack_trace": "javax.net.ssl.SSLHandshakeException: PKIX path validation failed: certificate expired on 2026-09-01T11:00:00Z\n\tat SecurityContext.java:112",
                },
            ],
            "deployments": [
                {
                    "id": "dep-user-201",
                    "service": "user-service",
                    "version": "v2.0.1",
                    "previous_version": "v2.0.0",
                    "timestamp": "2026-09-01T10:35:00Z",
                    "commit_hash": "11bc90a",
                    "author": "ian@company.com",
                    "commit_message": "chore: cleanup README and comments",
                    "rollback_version": "v2.0.0",
                    "changes": ["README.md: fix typos"],
                }
            ],
            "anomalies": [
                {
                    "metric_name": "error_rate_5xx_pct",
                    "onset_timestamp": "2026-09-01T11:00:00Z",
                    "peak_value": 85.0,
                    "baseline_mean": 0.00,
                    "summary": "error_rate_5xx_pct spiked to 85.00% starting at 2026-09-01T11:00:00Z",
                }
            ],
        },
        "expected": {
            "cause_category": "red_herring",
            "is_deploy_cause": False,
            "culprit_commit": None,
            "culprit_version": None,
            "exception_substring": "SSLHandshakeException",
            "faulty_file_and_line": "SecurityContext.java:112",
            "action_type": "MANUAL_INVESTIGATION",
            "min_confidence": 0.85,
            "evidence_keywords": ["SSLHandshakeException", "certificate expired", "PKIX", "benign"],
        },
    },
    {
        "id": "scenario_10_billing_db_deadlock_red_herring",
        "name": "Billing Service Database Concurrency Deadlock Red Herring",
        "service": "billing-service",
        "category": "red_herring",
        "description": "Benign deploy v1.4.0 (lint config) occurred 30 min ago. Concurrent payout batch job collided with subscription renewals causing MySQLTransactionRollbackException Deadlock. Deploy is NOT the cause.",
        "telemetry": {
            "logs": [
                {
                    "timestamp": "2026-09-01T14:00:00.000Z",
                    "level": "INFO",
                    "service": "billing-service",
                    "logger": "billing.main",
                    "message": "Billing service v1.4.0 active.",
                    "stack_trace": None,
                },
                {
                    "timestamp": "2026-09-01T14:30:15.220Z",
                    "level": "ERROR",
                    "service": "billing-service",
                    "logger": "billing.ledger",
                    "message": "Transaction failed while acquiring row lock on customer_ledger",
                    "stack_trace": "com.mysql.cj.jdbc.exceptions.MySQLTransactionRollbackException: Deadlock found when trying to get lock; try restarting transaction\n\tat BillingLedger.java:188\n\tat PayoutBatchJob.java:92\n\tat SubscriptionManager.java:140",
                },
                {
                    "timestamp": "2026-09-01T14:30:40.910Z",
                    "level": "ERROR",
                    "service": "billing-service",
                    "logger": "billing.ledger",
                    "message": "Transaction failed while acquiring row lock on customer_ledger",
                    "stack_trace": "com.mysql.cj.jdbc.exceptions.MySQLTransactionRollbackException: Deadlock found when trying to get lock; try restarting transaction\n\tat BillingLedger.java:188",
                },
            ],
            "deployments": [
                {
                    "id": "dep-billing-140",
                    "service": "billing-service",
                    "version": "v1.4.0",
                    "previous_version": "v1.3.9",
                    "timestamp": "2026-09-01T14:00:00Z",
                    "commit_hash": "88aa12d",
                    "author": "jane@company.com",
                    "commit_message": "chore: update linter rules",
                    "rollback_version": "v1.3.9",
                    "changes": [".eslintrc.json: rule adjustments"],
                }
            ],
            "anomalies": [
                {
                    "metric_name": "error_rate_5xx_pct",
                    "onset_timestamp": "2026-09-01T14:30:00Z",
                    "peak_value": 39.5,
                    "baseline_mean": 0.01,
                    "summary": "error_rate_5xx_pct spiked to 39.50% starting at 2026-09-01T14:30:00Z",
                }
            ],
        },
        "expected": {
            "cause_category": "red_herring",
            "is_deploy_cause": False,
            "culprit_commit": None,
            "culprit_version": None,
            "exception_substring": "Deadlock found",
            "faulty_file_and_line": "BillingLedger.java:188",
            "action_type": "MANUAL_INVESTIGATION",
            "min_confidence": 0.85,
            "evidence_keywords": ["Deadlock found", "MySQLTransactionRollbackException", "lock contention", "benign"],
        },
    },
]
