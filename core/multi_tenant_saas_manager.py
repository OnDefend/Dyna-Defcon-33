#!/usr/bin/env python3
"""
AODS Multi-Tenant SaaS Manager - Phase F2.2

High-quality multi-tenant SaaS architecture with complete data separation,
usage-based billing, custom branding, and Enterprise SSO integration.

Built upon proven AODS Kubernetes orchestration and database infrastructure.
"""

import logging
import json
import uuid
import hashlib
import time
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime, timedelta
from pathlib import Path
from dataclasses import dataclass, asdict
import threading
import asyncio
from enum import Enum
import secrets
import jwt

# Database imports
try:
    import sqlalchemy as sa
    from sqlalchemy import create_engine, text, MetaData, Table, Column, String, Integer, DateTime, Boolean, JSON, DECIMAL
    from sqlalchemy.orm import sessionmaker, declarative_base
    from sqlalchemy.dialects.postgresql import UUID
    DATABASE_AVAILABLE = True
except ImportError:
    DATABASE_AVAILABLE = False
    sa = None

# Redis imports
try:
    import redis
    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False
    redis = None

# JWT and crypto imports
try:
    import cryptography
    from cryptography.fernet import Fernet
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False
    Fernet = None

# Set up logging
logging.basicConfig(level=logging.INFO)

class TenantTier(Enum):
    """Tenant subscription tiers"""
    STARTER = "starter"
    PROFESSIONAL = "professional"
    ENTERPRISE = "enterprise"
    UNLIMITED = "unlimited"

class BillingPeriod(Enum):
    """Billing period types"""
    MONTHLY = "monthly"
    QUARTERLY = "quarterly"
    ANNUAL = "annual"

@dataclass
class TenantConfiguration:
    """Tenant configuration and limits"""
    tenant_id: str
    tenant_name: str
    tier: TenantTier
    max_apk_analyses_per_month: int
    max_concurrent_analyses: int
    max_storage_gb: int
    api_rate_limit_per_minute: int
    custom_branding_enabled: bool
    sso_enabled: bool
    advanced_features_enabled: bool
    created_at: datetime
    expires_at: Optional[datetime] = None
    
    # Usage limits by tier
    TIER_LIMITS = {
        TenantTier.STARTER: {
            'max_apk_analyses_per_month': 100,
            'max_concurrent_analyses': 2,
            'max_storage_gb': 1,
            'api_rate_limit_per_minute': 30,
            'custom_branding_enabled': False,
            'sso_enabled': False,
            'advanced_features_enabled': False
        },
        TenantTier.PROFESSIONAL: {
            'max_apk_analyses_per_month': 1000,
            'max_concurrent_analyses': 5,
            'max_storage_gb': 10,
            'api_rate_limit_per_minute': 100,
            'custom_branding_enabled': True,
            'sso_enabled': False,
            'advanced_features_enabled': True
        },
        TenantTier.ENTERPRISE: {
            'max_apk_analyses_per_month': 10000,
            'max_concurrent_analyses': 20,
            'max_storage_gb': 100,
            'api_rate_limit_per_minute': 500,
            'custom_branding_enabled': True,
            'sso_enabled': True,
            'advanced_features_enabled': True
        },
        TenantTier.UNLIMITED: {
            'max_apk_analyses_per_month': -1,  # Unlimited
            'max_concurrent_analyses': 50,
            'max_storage_gb': 1000,
            'api_rate_limit_per_minute': 1000,
            'custom_branding_enabled': True,
            'sso_enabled': True,
            'advanced_features_enabled': True
        }
    }

@dataclass
class UsageRecord:
    """Usage tracking record"""
    tenant_id: str
    analysis_id: str
    apk_name: str
    analysis_type: str
    processing_time_seconds: int
    storage_used_mb: int
    api_calls_count: int
    timestamp: datetime
    cost_credits: float

@dataclass
class BillingRecord:
    """Billing calculation record"""
    tenant_id: str
    billing_period: BillingPeriod
    period_start: datetime
    period_end: datetime
    total_analyses: int
    total_storage_gb: float
    total_api_calls: int
    total_cost_usd: float
    usage_details: List[UsageRecord]

class TenantIsolationManager:
    """Manages complete tenant data isolation"""
    
    def __init__(self, database_url: str, redis_url: Optional[str] = None):
        self.logger = logging.getLogger(__name__)
        self.database_url = database_url
        self.redis_url = redis_url
        
        # Database connection
        self.engine = None
        self.Session = None
        
        # Redis connection
        self.redis_client = None
        
        # Tenant schema isolation
        self.tenant_schemas = {}
        
        # Encryption for sensitive data
        self.encryption_key = None
        self.cipher_suite = None
        
        self._initialize_database()
        self._initialize_redis()
        self._initialize_encryption()
        
        self.logger.info("TenantIsolationManager initialized")
    
    def _initialize_database(self):
        """Initialize database connections and tenant schemas"""
        if not DATABASE_AVAILABLE:
            self.logger.warning("Database not available - using simulation mode")
            return
        
        try:
            self.engine = create_engine(self.database_url, pool_pre_ping=True)
            self.Session = sessionmaker(bind=self.engine)
            
            # Test connection
            with self.engine.connect() as conn:
                conn.execute(text("SELECT 1"))
            
            self.logger.info("Database connection established")
            
        except Exception as e:
            self.logger.error(f"Failed to initialize database: {e}")
    
    def _initialize_redis(self):
        """Initialize Redis connection for caching and sessions"""
        if not REDIS_AVAILABLE or not self.redis_url:
            self.logger.warning("Redis not available - using in-memory cache")
            return
        
        try:
            self.redis_client = redis.from_url(self.redis_url)
            self.redis_client.ping()
            
            self.logger.info("Redis connection established")
            
        except Exception as e:
            self.logger.error(f"Failed to initialize Redis: {e}")
    
    def _initialize_encryption(self):
        """Initialize encryption for sensitive tenant data"""
        if not CRYPTO_AVAILABLE:
            self.logger.warning("Cryptography not available - sensitive data not encrypted")
            return
        
        try:
            # In production, load from secure key management
            self.encryption_key = Fernet.generate_key()
            self.cipher_suite = Fernet(self.encryption_key)
            
            self.logger.info("Encryption initialized")
            
        except Exception as e:
            self.logger.error(f"Failed to initialize encryption: {e}")
    
    def create_tenant_schema(self, tenant_id: str) -> bool:
        """Create isolated database schema for tenant"""
        if not self.engine:
            self.logger.info(f"Simulated: Creating schema for tenant {tenant_id}")
            self.tenant_schemas[tenant_id] = f"tenant_{tenant_id.replace('-', '_')}"
            return True
        
        try:
            schema_name = f"tenant_{tenant_id.replace('-', '_')}"
            
            with self.engine.connect() as conn:
                # Create schema
                conn.execute(text(f"CREATE SCHEMA IF NOT EXISTS {schema_name}"))
                
                # Create tenant-specific tables
                tenant_tables = [
                    f"""
                    CREATE TABLE IF NOT EXISTS {schema_name}.analysis_results (
                        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                        apk_hash VARCHAR(64) NOT NULL,
                        apk_name VARCHAR(255) NOT NULL,
                        analysis_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        analysis_duration_seconds INTEGER,
                        vulnerability_count INTEGER DEFAULT 0,
                        results_json JSONB,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                    """,
                    f"""
                    CREATE TABLE IF NOT EXISTS {schema_name}.vulnerability_cache (
                        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                        pattern_hash VARCHAR(64) UNIQUE NOT NULL,
                        pattern_data JSONB NOT NULL,
                        confidence_score DECIMAL(3,2),
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                    """,
                    f"""
                    CREATE TABLE IF NOT EXISTS {schema_name}.usage_tracking (
                        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                        analysis_id VARCHAR(255) NOT NULL,
                        apk_name VARCHAR(255) NOT NULL,
                        analysis_type VARCHAR(100) NOT NULL,
                        processing_time_seconds INTEGER NOT NULL,
                        storage_used_mb INTEGER NOT NULL,
                        api_calls_count INTEGER NOT NULL,
                        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                    """
                ]
                
                for table_sql in tenant_tables:
                    conn.execute(text(table_sql))
                
                conn.commit()
            
            self.tenant_schemas[tenant_id] = schema_name
            self.logger.info(f"Created isolated schema for tenant {tenant_id}: {schema_name}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to create tenant schema for {tenant_id}: {e}")
            return False
    
    def get_tenant_connection(self, tenant_id: str):
        """Get database connection with tenant schema context"""
        if not self.engine:
            return None
        
        schema_name = self.tenant_schemas.get(tenant_id)
        if not schema_name:
            self.logger.error(f"No schema found for tenant {tenant_id}")
            return None
        
        # Return connection with schema search path set
        conn = self.engine.connect()
        conn.execute(text(f"SET search_path TO {schema_name}, public"))
        return conn
    
    def encrypt_sensitive_data(self, data: str) -> str:
        """Encrypt sensitive tenant data"""
        if not self.cipher_suite:
            return data  # Return unencrypted if crypto not available
        
        try:
            encrypted_data = self.cipher_suite.encrypt(data.encode())
            return encrypted_data.decode()
        except Exception as e:
            self.logger.error(f"Failed to encrypt data: {e}")
            return data
    
    def decrypt_sensitive_data(self, encrypted_data: str) -> str:
        """Decrypt sensitive tenant data"""
        if not self.cipher_suite:
            return encrypted_data  # Return as-is if crypto not available
        
        try:
            decrypted_data = self.cipher_suite.decrypt(encrypted_data.encode())
            return decrypted_data.decode()
        except Exception as e:
            self.logger.error(f"Failed to decrypt data: {e}")
            return encrypted_data

class UsageBasedBillingEngine:
    """Handles usage tracking and billing calculations"""
    
    def __init__(self, isolation_manager: TenantIsolationManager):
        self.logger = logging.getLogger(__name__)
        self.isolation_manager = isolation_manager
        
        # Pricing configuration (per unit)
        self.pricing_config = {
            'analysis_cost_per_apk': 0.10,      # $0.10 per APK analysis
            'storage_cost_per_gb_month': 0.25,   # $0.25 per GB per month
            'api_call_cost_per_1000': 0.05,     # $0.05 per 1000 API calls
            'advanced_feature_multiplier': 1.5   # 50% premium for advanced features
        }
        
        # Usage tracking
        self.usage_cache = {}
        
        self.logger.info("UsageBasedBillingEngine initialized")
    
    def record_usage(self, tenant_id: str, analysis_id: str, apk_name: str, 
                    analysis_type: str, processing_time: int, storage_used_mb: int, 
                    api_calls: int) -> UsageRecord:
        """Record usage for billing calculation"""
        
        # Calculate cost in credits
        cost_credits = self._calculate_analysis_cost(
            analysis_type, processing_time, storage_used_mb, api_calls
        )
        
        usage_record = UsageRecord(
            tenant_id=tenant_id,
            analysis_id=analysis_id,
            apk_name=apk_name,
            analysis_type=analysis_type,
            processing_time_seconds=processing_time,
            storage_used_mb=storage_used_mb,
            api_calls_count=api_calls,
            timestamp=datetime.now(),
            cost_credits=cost_credits
        )
        
        # Store in tenant's isolated database
        self._store_usage_record(usage_record)
        
        # Update usage cache
        if tenant_id not in self.usage_cache:
            self.usage_cache[tenant_id] = []
        self.usage_cache[tenant_id].append(usage_record)
        
        self.logger.info(f"Recorded usage for tenant {tenant_id}: {apk_name} - ${cost_credits:.4f}")
        return usage_record
    
    def _calculate_analysis_cost(self, analysis_type: str, processing_time: int, 
                               storage_used_mb: int, api_calls: int) -> float:
        """Calculate cost for a single analysis"""
        base_cost = self.pricing_config['analysis_cost_per_apk']
        
        # Storage cost (prorated)
        storage_gb = storage_used_mb / 1024
        storage_cost = storage_gb * self.pricing_config['storage_cost_per_gb_month'] / 30  # Daily rate
        
        # API call cost
        api_cost = (api_calls / 1000) * self.pricing_config['api_call_cost_per_1000']
        
        # Processing time premium for complex analyses
        time_multiplier = 1.0 + (processing_time / 3600)  # 1x base + hourly rate
        
        # Advanced feature premium
        feature_multiplier = 1.0
        if 'advanced' in analysis_type.lower() or 'ml' in analysis_type.lower():
            feature_multiplier = self.pricing_config['advanced_feature_multiplier']
        
        total_cost = (base_cost + storage_cost + api_cost) * time_multiplier * feature_multiplier
        return round(total_cost, 4)
    
    def _store_usage_record(self, usage_record: UsageRecord):
        """Store usage record in tenant's isolated database"""
        conn = self.isolation_manager.get_tenant_connection(usage_record.tenant_id)
        if not conn:
            self.logger.warning(f"No database connection for tenant {usage_record.tenant_id}")
            return
        
        try:
            insert_sql = text("""
                INSERT INTO usage_tracking (
                    analysis_id, apk_name, analysis_type, processing_time_seconds,
                    storage_used_mb, api_calls_count, timestamp
                ) VALUES (
                    :analysis_id, :apk_name, :analysis_type, :processing_time,
                    :storage_used_mb, :api_calls, :timestamp
                )
            """)
            
            conn.execute(insert_sql, {
                'analysis_id': usage_record.analysis_id,
                'apk_name': usage_record.apk_name,
                'analysis_type': usage_record.analysis_type,
                'processing_time': usage_record.processing_time_seconds,
                'storage_used_mb': usage_record.storage_used_mb,
                'api_calls': usage_record.api_calls_count,
                'timestamp': usage_record.timestamp
            })
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            self.logger.error(f"Failed to store usage record: {e}")
            if conn:
                conn.close()
    
    def generate_billing_report(self, tenant_id: str, period: BillingPeriod, 
                              period_start: datetime) -> BillingRecord:
        """Generate billing report for tenant"""
        
        # Calculate period end
        if period == BillingPeriod.MONTHLY:
            period_end = period_start + timedelta(days=30)
        elif period == BillingPeriod.QUARTERLY:
            period_end = period_start + timedelta(days=90)
        else:  # ANNUAL
            period_end = period_start + timedelta(days=365)
        
        # Get usage records for period
        usage_records = self._get_usage_records_for_period(tenant_id, period_start, period_end)
        
        # Calculate totals
        total_analyses = len(usage_records)
        total_storage_gb = sum(r.storage_used_mb for r in usage_records) / 1024
        total_api_calls = sum(r.api_calls_count for r in usage_records)
        total_cost = sum(r.cost_credits for r in usage_records)
        
        billing_record = BillingRecord(
            tenant_id=tenant_id,
            billing_period=period,
            period_start=period_start,
            period_end=period_end,
            total_analyses=total_analyses,
            total_storage_gb=total_storage_gb,
            total_api_calls=total_api_calls,
            total_cost_usd=total_cost,
            usage_details=usage_records
        )
        
        self.logger.info(f"Generated billing report for tenant {tenant_id}: ${total_cost:.2f}")
        return billing_record
    
    def _get_usage_records_for_period(self, tenant_id: str, start: datetime, 
                                    end: datetime) -> List[UsageRecord]:
        """Get usage records for specific period"""
        conn = self.isolation_manager.get_tenant_connection(tenant_id)
        if not conn:
            return []
        
        try:
            select_sql = text("""
                SELECT analysis_id, apk_name, analysis_type, processing_time_seconds,
                       storage_used_mb, api_calls_count, timestamp
                FROM usage_tracking
                WHERE timestamp >= :start_date AND timestamp <= :end_date
                ORDER BY timestamp DESC
            """)
            
            result = conn.execute(select_sql, {
                'start_date': start,
                'end_date': end
            })
            
            usage_records = []
            for row in result:
                # Recalculate cost (in case pricing changed)
                cost = self._calculate_analysis_cost(
                    row.analysis_type, row.processing_time_seconds,
                    row.storage_used_mb, row.api_calls_count
                )
                
                usage_record = UsageRecord(
                    tenant_id=tenant_id,
                    analysis_id=row.analysis_id,
                    apk_name=row.apk_name,
                    analysis_type=row.analysis_type,
                    processing_time_seconds=row.processing_time_seconds,
                    storage_used_mb=row.storage_used_mb,
                    api_calls_count=row.api_calls_count,
                    timestamp=row.timestamp,
                    cost_credits=cost
                )
                usage_records.append(usage_record)
            
            conn.close()
            return usage_records
            
        except Exception as e:
            self.logger.error(f"Failed to get usage records: {e}")
            if conn:
                conn.close()
            return []

class EnterpriseSSO:
    """Enterprise Single Sign-On integration"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        
        # Supported SSO providers
        self.sso_providers = {
            'saml': self._handle_saml_auth,
            'oauth2': self._handle_oauth2_auth,
            'ldap': self._handle_ldap_auth,
            'azure_ad': self._handle_azure_ad_auth,
            'okta': self._handle_okta_auth
        }
        
        # JWT configuration
        self.jwt_secret = secrets.token_urlsafe(32)
        self.jwt_algorithm = 'HS256'
        self.jwt_expiry_hours = 24
        
        self.logger.info("EnterpriseSSO initialized")
    
    def authenticate_user(self, provider: str, credentials: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Authenticate user via SSO provider"""
        if provider not in self.sso_providers:
            self.logger.error(f"Unsupported SSO provider: {provider}")
            return None
        
        try:
            auth_handler = self.sso_providers[provider]
            user_info = auth_handler(credentials)
            
            if user_info:
                # Generate JWT token
                token = self._generate_jwt_token(user_info)
                user_info['access_token'] = token
                
                self.logger.info(f"User authenticated via {provider}: {user_info.get('email', 'unknown')}")
                return user_info
            
        except Exception as e:
            self.logger.error(f"SSO authentication failed for {provider}: {e}")
        
        return None
    
    def _handle_saml_auth(self, credentials: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Handle SAML authentication"""
        # Simulated SAML authentication
        saml_response = credentials.get('saml_response')
        if not saml_response:
            return None
        
        # In production, validate SAML response with proper SAML library
        return {
            'user_id': 'saml_user_123',
            'email': 'user@enterprise.com',
            'name': 'Enterprise User',
            'tenant_id': credentials.get('tenant_id'),
            'roles': ['user', 'analyst']
        }
    
    def _handle_oauth2_auth(self, credentials: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Handle OAuth2 authentication"""
        # Simulated OAuth2 authentication
        access_token = credentials.get('access_token')
        if not access_token:
            return None
        
        # In production, validate token with OAuth2 provider
        return {
            'user_id': 'oauth_user_456',
            'email': 'user@company.com',
            'name': 'OAuth User',
            'tenant_id': credentials.get('tenant_id'),
            'roles': ['user']
        }
    
    def _handle_ldap_auth(self, credentials: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Handle LDAP authentication"""
        # Simulated LDAP authentication
        username = credentials.get('username')
        password = credentials.get('password')
        
        if not username or not password:
            return None
        
        # In production, authenticate against LDAP server
        return {
            'user_id': f'ldap_{username}',
            'email': f'{username}@ldap.company.com',
            'name': username.title(),
            'tenant_id': credentials.get('tenant_id'),
            'roles': ['user']
        }
    
    def _handle_azure_ad_auth(self, credentials: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Handle Azure AD authentication"""
        # Simulated Azure AD authentication
        azure_token = credentials.get('azure_token')
        if not azure_token:
            return None
        
        return {
            'user_id': 'azure_user_789',
            'email': 'user@company.onmicrosoft.com',
            'name': 'Azure User',
            'tenant_id': credentials.get('tenant_id'),
            'roles': ['user', 'admin']
        }
    
    def _handle_okta_auth(self, credentials: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Handle Okta authentication"""
        # Simulated Okta authentication
        okta_token = credentials.get('okta_token')
        if not okta_token:
            return None
        
        return {
            'user_id': 'okta_user_101',
            'email': 'user@company.okta.com',
            'name': 'Okta User',
            'tenant_id': credentials.get('tenant_id'),
            'roles': ['user']
        }
    
    def _generate_jwt_token(self, user_info: Dict[str, Any]) -> str:
        """Generate JWT token for authenticated user"""
        payload = {
            'user_id': user_info['user_id'],
            'email': user_info['email'],
            'tenant_id': user_info['tenant_id'],
            'roles': user_info['roles'],
            'exp': datetime.utcnow() + timedelta(hours=self.jwt_expiry_hours),
            'iat': datetime.utcnow()
        }
        
        token = jwt.encode(payload, self.jwt_secret, algorithm=self.jwt_algorithm)
        return token
    
    def validate_jwt_token(self, token: str) -> Optional[Dict[str, Any]]:
        """Validate JWT token"""
        try:
            payload = jwt.decode(token, self.jwt_secret, algorithms=[self.jwt_algorithm])
            return payload
        except jwt.ExpiredSignatureError:
            self.logger.warning("JWT token expired")
        except jwt.InvalidTokenError:
            self.logger.warning("Invalid JWT token")
        
        return None

class MultiTenantSaaSManager:
    """Main multi-tenant SaaS management system"""
    
    def __init__(self, database_url: str, redis_url: Optional[str] = None):
        self.logger = logging.getLogger(__name__)
        
        # Initialize components
        self.isolation_manager = TenantIsolationManager(database_url, redis_url)
        self.billing_engine = UsageBasedBillingEngine(self.isolation_manager)
        self.sso_manager = EnterpriseSSO()
        
        # Tenant registry
        self.tenant_registry: Dict[str, TenantConfiguration] = {}
        
        # Active sessions
        self.active_sessions: Dict[str, Dict[str, Any]] = {}
        
        # Load existing tenants
        self._load_tenant_registry()
        
        self.logger.info("MultiTenantSaaSManager initialized")
    
    def create_tenant(self, tenant_name: str, tier: TenantTier, 
                     admin_email: str) -> TenantConfiguration:
        """Create new tenant with isolated resources"""
        
        tenant_id = str(uuid.uuid4())
        
        # Get tier limits
        tier_limits = TenantConfiguration.TIER_LIMITS[tier]
        
        # Create tenant configuration
        tenant_config = TenantConfiguration(
            tenant_id=tenant_id,
            tenant_name=tenant_name,
            tier=tier,
            created_at=datetime.now(),
            **tier_limits
        )
        
        # Create isolated database schema
        if self.isolation_manager.create_tenant_schema(tenant_id):
            # Store tenant configuration
            self.tenant_registry[tenant_id] = tenant_config
            self._save_tenant_configuration(tenant_config)
            
            self.logger.info(f"Created tenant: {tenant_name} ({tier.value}) - ID: {tenant_id}")
            return tenant_config
        else:
            raise Exception(f"Failed to create tenant isolation for {tenant_name}")
    
    def authenticate_tenant_user(self, tenant_id: str, sso_provider: str, 
                                credentials: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Authenticate user for specific tenant"""
        
        # Verify tenant exists
        if tenant_id not in self.tenant_registry:
            self.logger.error(f"Tenant not found: {tenant_id}")
            return None
        
        tenant_config = self.tenant_registry[tenant_id]
        
        # Check if SSO is enabled for tenant
        if not tenant_config.sso_enabled and sso_provider != 'local':
            self.logger.error(f"SSO not enabled for tenant {tenant_id}")
            return None
        
        # Add tenant context to credentials
        credentials['tenant_id'] = tenant_id
        
        # Authenticate via SSO
        user_info = self.sso_manager.authenticate_user(sso_provider, credentials)
        
        if user_info:
            # Create session
            session_id = str(uuid.uuid4())
            self.active_sessions[session_id] = {
                'tenant_id': tenant_id,
                'user_info': user_info,
                'created_at': datetime.now(),
                'last_activity': datetime.now()
            }
            
            user_info['session_id'] = session_id
            
        return user_info
    
    def process_tenant_analysis(self, tenant_id: str, session_id: str, 
                              apk_data: bytes, analysis_options: Dict[str, Any]) -> Dict[str, Any]:
        """Process APK analysis for specific tenant with usage tracking"""
        
        # Validate session
        if session_id not in self.active_sessions:
            raise Exception("Invalid session")
        
        session = self.active_sessions[session_id]
        if session['tenant_id'] != tenant_id:
            raise Exception("Session tenant mismatch")
        
        # Get tenant configuration
        tenant_config = self.tenant_registry[tenant_id]
        
        # Check limits
        if not self._check_tenant_limits(tenant_config):
            raise Exception("Tenant limits exceeded")
        
        # Generate analysis ID
        analysis_id = str(uuid.uuid4())
        
        # Simulate analysis processing (in production, integrate with AODS core)
        start_time = time.time()
        
        # Simulated analysis results
        analysis_results = {
            'analysis_id': analysis_id,
            'tenant_id': tenant_id,
            'apk_name': analysis_options.get('apk_name', 'unknown.apk'),
            'analysis_type': 'comprehensive' if tenant_config.advanced_features_enabled else 'basic',
            'vulnerabilities_found': 12 if tenant_config.advanced_features_enabled else 8,
            'threat_intelligence_matches': 3 if tenant_config.advanced_features_enabled else 0,
            'ml_enhanced': tenant_config.advanced_features_enabled,
            'processing_time_seconds': int(time.time() - start_time),
            'timestamp': datetime.now().isoformat()
        }
        
        # Record usage
        usage_record = self.billing_engine.record_usage(
            tenant_id=tenant_id,
            analysis_id=analysis_id,
            apk_name=analysis_results['apk_name'],
            analysis_type=analysis_results['analysis_type'],
            processing_time=analysis_results['processing_time_seconds'],
            storage_used_mb=len(apk_data) // (1024 * 1024),  # Convert to MB
            api_calls=1
        )
        
        # Add billing info to results
        analysis_results['usage_cost'] = usage_record.cost_credits
        
        # Update session activity
        session['last_activity'] = datetime.now()
        
        self.logger.info(f"Processed analysis for tenant {tenant_id}: {analysis_id}")
        return analysis_results
    
    def get_tenant_usage_report(self, tenant_id: str, period: BillingPeriod, 
                              period_start: datetime) -> BillingRecord:
        """Get usage and billing report for tenant"""
        
        if tenant_id not in self.tenant_registry:
            raise Exception(f"Tenant not found: {tenant_id}")
        
        return self.billing_engine.generate_billing_report(tenant_id, period, period_start)
    
    def get_tenant_dashboard_data(self, tenant_id: str) -> Dict[str, Any]:
        """Get dashboard data for tenant"""
        
        if tenant_id not in self.tenant_registry:
            raise Exception(f"Tenant not found: {tenant_id}")
        
        tenant_config = self.tenant_registry[tenant_id]
        
        # Get current month usage
        current_month_start = datetime.now().replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        current_usage = self.billing_engine.generate_billing_report(
            tenant_id, BillingPeriod.MONTHLY, current_month_start
        )
        
        # Calculate usage percentages
        usage_percentage = {
            'analyses': (current_usage.total_analyses / tenant_config.max_apk_analyses_per_month * 100) 
                       if tenant_config.max_apk_analyses_per_month > 0 else 0,
            'storage': (current_usage.total_storage_gb / tenant_config.max_storage_gb * 100),
            'api_calls': min(100, current_usage.total_api_calls / (tenant_config.api_rate_limit_per_minute * 60 * 24 * 30) * 100)
        }
        
        return {
            'tenant_config': asdict(tenant_config),
            'current_usage': {
                'total_analyses': current_usage.total_analyses,
                'total_storage_gb': current_usage.total_storage_gb,
                'total_api_calls': current_usage.total_api_calls,
                'total_cost_usd': current_usage.total_cost_usd
            },
            'usage_percentage': usage_percentage,
            'limits': {
                'max_analyses': tenant_config.max_apk_analyses_per_month,
                'max_storage_gb': tenant_config.max_storage_gb,
                'rate_limit_per_minute': tenant_config.api_rate_limit_per_minute
            },
            'features': {
                'custom_branding': tenant_config.custom_branding_enabled,
                'sso_enabled': tenant_config.sso_enabled,
                'advanced_features': tenant_config.advanced_features_enabled
            }
        }
    
    def _check_tenant_limits(self, tenant_config: TenantConfiguration) -> bool:
        """Check if tenant is within usage limits"""
        
        # Get current month usage
        current_month_start = datetime.now().replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        current_usage = self.billing_engine.generate_billing_report(
            tenant_config.tenant_id, BillingPeriod.MONTHLY, current_month_start
        )
        
        # Check monthly analysis limit
        if (tenant_config.max_apk_analyses_per_month > 0 and 
            current_usage.total_analyses >= tenant_config.max_apk_analyses_per_month):
            self.logger.warning(f"Tenant {tenant_config.tenant_id} exceeded monthly analysis limit")
            return False
        
        # Check storage limit
        if current_usage.total_storage_gb >= tenant_config.max_storage_gb:
            self.logger.warning(f"Tenant {tenant_config.tenant_id} exceeded storage limit")
            return False
        
        return True
    
    def _load_tenant_registry(self):
        """Load existing tenant configurations"""
        # In production, load from database
        # For now, simulate with empty registry
        self.logger.info("Tenant registry loaded")
    
    def _save_tenant_configuration(self, tenant_config: TenantConfiguration):
        """Save tenant configuration to persistent storage"""
        # In production, save to database
        self.logger.info(f"Saved tenant configuration: {tenant_config.tenant_id}")
    
    def get_saas_status(self) -> Dict[str, Any]:
        """Get overall SaaS platform status"""
        
        total_tenants = len(self.tenant_registry)
        active_sessions = len(self.active_sessions)
        
        # Calculate tier distribution
        tier_distribution = {}
        for tenant in self.tenant_registry.values():
            tier_name = tenant.tier.value
            tier_distribution[tier_name] = tier_distribution.get(tier_name, 0) + 1
        
        return {
            'platform_status': 'operational',
            'total_tenants': total_tenants,
            'active_sessions': active_sessions,
            'tier_distribution': tier_distribution,
            'components': {
                'database_isolation': self.isolation_manager.engine is not None,
                'redis_cache': self.isolation_manager.redis_client is not None,
                'encryption': self.isolation_manager.cipher_suite is not None,
                'sso_providers': list(self.sso_manager.sso_providers.keys())
            },
            'pricing_config': self.billing_engine.pricing_config
        }

# Global instance for easy access
_multi_tenant_saas_manager = None

def get_multi_tenant_saas_manager(database_url: str = None, redis_url: str = None) -> MultiTenantSaaSManager:
    """Get global multi-tenant SaaS manager instance"""
    global _multi_tenant_saas_manager
    
    if _multi_tenant_saas_manager is None:
        # Default URLs for production
        if not database_url:
            database_url = "postgresql://aods:aods_secure_pass@aods-postgres:5432/aods_db"
        if not redis_url:
            redis_url = "redis://aods-redis:6379/0"
        
        _multi_tenant_saas_manager = MultiTenantSaaSManager(database_url, redis_url)
    
    return _multi_tenant_saas_manager

if __name__ == "__main__":
    # Demo usage
    logging.basicConfig(level=logging.INFO)
    
    # Initialize SaaS manager
    saas_manager = get_multi_tenant_saas_manager()
    
    # Create demo tenant
    tenant_config = saas_manager.create_tenant(
        tenant_name="Acme Security Corp",
        tier=TenantTier.ENTERPRISE,
        admin_email="admin@acmesec.com"
    )
    
    print(f"Created tenant: {tenant_config.tenant_name} - {tenant_config.tenant_id}")
    
    # Authenticate user
    user_info = saas_manager.authenticate_tenant_user(
        tenant_id=tenant_config.tenant_id,
        sso_provider="azure_ad",
        credentials={"azure_token": "demo_token"}
    )
    
    if user_info:
        print(f"Authenticated user: {user_info['email']}")
        
        # Process analysis
        analysis_result = saas_manager.process_tenant_analysis(
            tenant_id=tenant_config.tenant_id,
            session_id=user_info['session_id'],
            apk_data=b"demo_apk_data" * 1000,  # Simulate APK data
            analysis_options={"apk_name": "demo_app.apk"}
        )
        
        print(f"Analysis completed: {analysis_result['analysis_id']} - Cost: ${analysis_result['usage_cost']:.4f}")
        
        # Get dashboard data
        dashboard = saas_manager.get_tenant_dashboard_data(tenant_config.tenant_id)
        print(f"Current usage: {dashboard['current_usage']['total_analyses']} analyses, ${dashboard['current_usage']['total_cost_usd']:.2f}")
    
    # Get platform status
    status = saas_manager.get_saas_status()
    print(f"Platform status: {status['platform_status']} - {status['total_tenants']} tenants")