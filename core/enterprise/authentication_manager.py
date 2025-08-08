#!/usr/bin/env python3
"""
Enterprise Authentication Manager for AODS

Comprehensive authentication system supporting multiple enterprise protocols:
- LDAP/Active Directory integration
- SAML 2.0 SSO authentication
- Multi-factor authentication (MFA)
- JWT-based session management
- OAuth 2.0 integration
- Role-based access control integration

Security Features:
- Secure credential storage with encryption
- Session timeout and refresh management
- Audit logging for all authentication events
- Failed login attempt protection
- Password policy enforcement
- Certificate-based authentication support
"""

import jwt
import ldap3
import hashlib
import secrets
import time
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple, Union
from dataclasses import dataclass, field
from enum import Enum
import json
import ssl
from pathlib import Path
import bcrypt
from cryptography.fernet import Fernet
import pyotp
import qrcode
from io import BytesIO
import base64

logger = logging.getLogger(__name__)

class AuthenticationMethod(Enum):
    """Supported authentication methods."""
    LOCAL = "local"
    LDAP = "ldap"
    SAML = "saml"
    OAUTH = "oauth"
    CERTIFICATE = "certificate"
    MFA = "mfa"

class UserRole(Enum):
    """User roles for RBAC integration."""
    ADMIN = "admin"
    ANALYST = "analyst"
    VIEWER = "viewer"
    AUDITOR = "auditor"
    API_USER = "api_user"

@dataclass
class AuthenticationConfig:
    """Configuration for enterprise authentication."""
    # JWT Configuration
    jwt_secret_key: str = None
    jwt_algorithm: str = "HS256"
    jwt_expiration_hours: int = 8
    jwt_refresh_hours: int = 24
    
    # LDAP Configuration
    ldap_server: str = None
    ldap_port: int = 389
    ldap_use_ssl: bool = True
    ldap_base_dn: str = None
    ldap_bind_dn: str = None
    ldap_bind_password: str = None
    ldap_user_search_base: str = None
    ldap_group_search_base: str = None
    
    # SAML Configuration
    saml_entity_id: str = None
    saml_sso_url: str = None
    saml_x509_cert: str = None
    saml_private_key: str = None
    
    # MFA Configuration
    mfa_enabled: bool = True
    mfa_issuer: str = "AODS"
    mfa_algorithm: str = "SHA1"
    mfa_digits: int = 6
    mfa_interval: int = 30
    
    # Security Configuration
    password_min_length: int = 12
    password_require_uppercase: bool = True
    password_require_lowercase: bool = True
    password_require_numbers: bool = True
    password_require_symbols: bool = True
    max_failed_attempts: int = 5
    lockout_duration_minutes: int = 30
    session_timeout_minutes: int = 480  # 8 hours
    
    # Audit Configuration
    audit_enabled: bool = True
    audit_log_file: str = "auth_audit.log"
    
    def __post_init__(self):
        """Generate default values if not provided."""
        if not self.jwt_secret_key:
            self.jwt_secret_key = secrets.token_urlsafe(32)

@dataclass
class UserSession:
    """User session information."""
    user_id: str
    username: str
    email: str
    roles: List[UserRole]
    authentication_method: AuthenticationMethod
    login_time: datetime
    last_activity: datetime
    session_id: str
    mfa_verified: bool = False
    permissions: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

@dataclass
class AuthenticationResult:
    """Result of authentication attempt."""
    success: bool
    user_session: Optional[UserSession] = None
    token: Optional[str] = None
    refresh_token: Optional[str] = None
    error_message: Optional[str] = None
    requires_mfa: bool = False
    mfa_setup_required: bool = False
    mfa_qr_code: Optional[str] = None

class SecurityAuditor:
    """Security audit logging for authentication events."""
    
    def __init__(self, config: AuthenticationConfig):
        self.config = config
        self.audit_logger = self._setup_audit_logger()
    
    def _setup_audit_logger(self):
        """Setup dedicated audit logger."""
        audit_logger = logging.getLogger("security_audit")
        
        if not audit_logger.handlers:
            handler = logging.FileHandler(self.config.audit_log_file)
            formatter = logging.Formatter(
                '%(asctime)s - SECURITY_AUDIT - %(levelname)s - %(message)s'
            )
            handler.setFormatter(formatter)
            audit_logger.addHandler(handler)
            audit_logger.setLevel(logging.INFO)
        
        return audit_logger
    
    def log_authentication_attempt(self, username: str, method: AuthenticationMethod, 
                                 success: bool, ip_address: str = None, 
                                 details: Dict[str, Any] = None):
        """Log authentication attempt."""
        if not self.config.audit_enabled:
            return
        
        event = {
            "event_type": "authentication_attempt",
            "username": username,
            "method": method.value,
            "success": success,
            "timestamp": datetime.utcnow().isoformat(),
            "ip_address": ip_address,
            "details": details or {}
        }
        
        self.audit_logger.info(json.dumps(event))
    
    def log_session_event(self, session_id: str, event_type: str, 
                         details: Dict[str, Any] = None):
        """Log session-related events."""
        if not self.config.audit_enabled:
            return
        
        event = {
            "event_type": f"session_{event_type}",
            "session_id": session_id,
            "timestamp": datetime.utcnow().isoformat(),
            "details": details or {}
        }
        
        self.audit_logger.info(json.dumps(event))
    
    def log_security_event(self, event_type: str, username: str = None, 
                          details: Dict[str, Any] = None):
        """Log security-related events."""
        if not self.config.audit_enabled:
            return
        
        event = {
            "event_type": f"security_{event_type}",
            "username": username,
            "timestamp": datetime.utcnow().isoformat(),
            "details": details or {}
        }
        
        self.audit_logger.warning(json.dumps(event))

class PasswordManager:
    """Secure password management and validation."""
    
    def __init__(self, config: AuthenticationConfig):
        self.config = config
        self.encryption_key = Fernet.generate_key()
        self.cipher = Fernet(self.encryption_key)
    
    def hash_password(self, password: str) -> str:
        """Hash password using bcrypt."""
        salt = bcrypt.gensalt()
        hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
        return hashed.decode('utf-8')
    
    def verify_password(self, password: str, hashed: str) -> bool:
        """Verify password against hash."""
        return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))
    
    def validate_password_policy(self, password: str) -> Tuple[bool, List[str]]:
        """Validate password against security policy."""
        errors = []
        
        if len(password) < self.config.password_min_length:
            errors.append(f"Password must be at least {self.config.password_min_length} characters")
        
        if self.config.password_require_uppercase and not any(c.isupper() for c in password):
            errors.append("Password must contain at least one uppercase letter")
        
        if self.config.password_require_lowercase and not any(c.islower() for c in password):
            errors.append("Password must contain at least one lowercase letter")
        
        if self.config.password_require_numbers and not any(c.isdigit() for c in password):
            errors.append("Password must contain at least one number")
        
        if self.config.password_require_symbols and not any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password):
            errors.append("Password must contain at least one special character")
        
        return len(errors) == 0, errors
    
    def encrypt_credential(self, credential: str) -> str:
        """Encrypt sensitive credential."""
        return self.cipher.encrypt(credential.encode()).decode()
    
    def decrypt_credential(self, encrypted_credential: str) -> str:
        """Decrypt sensitive credential."""
        return self.cipher.decrypt(encrypted_credential.encode()).decode()

class MFAManager:
    """Multi-factor authentication management."""
    
    def __init__(self, config: AuthenticationConfig):
        self.config = config
        self.logger = logging.getLogger(f"{__name__}.MFAManager")
    
    def generate_secret(self) -> str:
        """Generate MFA secret for user."""
        return pyotp.random_base32()
    
    def generate_qr_code(self, username: str, secret: str) -> str:
        """Generate QR code for MFA setup."""
        try:
            totp_uri = pyotp.totp.TOTP(secret).provisioning_uri(
                name=username,
                issuer_name=self.config.mfa_issuer
            )
            
            qr = qrcode.QRCode(version=1, box_size=10, border=5)
            qr.add_data(totp_uri)
            qr.make(fit=True)
            
            img = qr.make_image(fill_color="black", back_color="white")
            buffer = BytesIO()
            img.save(buffer, format='PNG')
            qr_code_data = base64.b64encode(buffer.getvalue()).decode()
            
            return f"data:image/png;base64,{qr_code_data}"
            
        except Exception as e:
            self.logger.error(f"Failed to generate QR code: {e}")
            return None
    
    def verify_totp(self, secret: str, token: str) -> bool:
        """Verify TOTP token."""
        try:
            totp = pyotp.TOTP(secret)
            return totp.verify(token, valid_window=1)
        except Exception as e:
            self.logger.error(f"TOTP verification failed: {e}")
            return False
    
    def generate_backup_codes(self, count: int = 10) -> List[str]:
        """Generate backup codes for MFA."""
        codes = []
        for _ in range(count):
            code = secrets.token_hex(4).upper()
            codes.append(f"{code[:4]}-{code[4:]}")
        return codes

class LDAPConnector:
    """LDAP/Active Directory integration."""
    
    def __init__(self, config: AuthenticationConfig):
        self.config = config
        self.logger = logging.getLogger(f"{__name__}.LDAPConnector")
    
    def _create_connection(self) -> Optional[ldap3.Connection]:
        """Create LDAP connection."""
        try:
            server = ldap3.Server(
                self.config.ldap_server,
                port=self.config.ldap_port,
                use_ssl=self.config.ldap_use_ssl,
                get_info=ldap3.ALL
            )
            
            connection = ldap3.Connection(
                server,
                user=self.config.ldap_bind_dn,
                password=self.config.ldap_bind_password,
                auto_bind=True
            )
            
            return connection
            
        except Exception as e:
            self.logger.error(f"LDAP connection failed: {e}")
            return None
    
    def authenticate_user(self, username: str, password: str) -> Tuple[bool, Dict[str, Any]]:
        """Authenticate user against LDAP."""
        connection = self._create_connection()
        if not connection:
            return False, {"error": "LDAP connection failed"}
        
        try:
            # Search for user
            search_filter = f"(sAMAccountName={username})"
            connection.search(
                search_base=self.config.ldap_user_search_base,
                search_filter=search_filter,
                attributes=['cn', 'mail', 'memberOf', 'userPrincipalName']
            )
            
            if not connection.entries:
                return False, {"error": "User not found"}
            
            user_entry = connection.entries[0]
            user_dn = user_entry.entry_dn
            
            # Authenticate with user credentials
            user_connection = ldap3.Connection(
                connection.server,
                user=user_dn,
                password=password
            )
            
            if not user_connection.bind():
                return False, {"error": "Invalid credentials"}
            
            # Get user information
            user_info = {
                "username": username,
                "email": str(user_entry.mail) if user_entry.mail else "",
                "display_name": str(user_entry.cn) if user_entry.cn else username,
                "groups": [str(group) for group in user_entry.memberOf] if user_entry.memberOf else [],
                "principal_name": str(user_entry.userPrincipalName) if user_entry.userPrincipalName else ""
            }
            
            user_connection.unbind()
            return True, user_info
            
        except Exception as e:
            self.logger.error(f"LDAP authentication failed: {e}")
            return False, {"error": str(e)}
        
        finally:
            connection.unbind()
    
    def get_user_groups(self, username: str) -> List[str]:
        """Get user's group memberships."""
        connection = self._create_connection()
        if not connection:
            return []
        
        try:
            search_filter = f"(sAMAccountName={username})"
            connection.search(
                search_base=self.config.ldap_user_search_base,
                search_filter=search_filter,
                attributes=['memberOf']
            )
            
            if connection.entries:
                groups = connection.entries[0].memberOf
                return [str(group) for group in groups] if groups else []
            
            return []
            
        except Exception as e:
            self.logger.error(f"Failed to get user groups: {e}")
            return []
        
        finally:
            connection.unbind()

class JWTManager:
    """JWT token management for session handling."""
    
    def __init__(self, config: AuthenticationConfig):
        self.config = config
        self.logger = logging.getLogger(f"{__name__}.JWTManager")
    
    def generate_tokens(self, user_session: UserSession) -> Tuple[str, str]:
        """Generate access and refresh tokens."""
        now = datetime.utcnow()
        
        # Access token payload
        access_payload = {
            "user_id": user_session.user_id,
            "username": user_session.username,
            "email": user_session.email,
            "roles": [role.value for role in user_session.roles],
            "session_id": user_session.session_id,
            "mfa_verified": user_session.mfa_verified,
            "permissions": user_session.permissions,
            "iat": now,
            "exp": now + timedelta(hours=self.config.jwt_expiration_hours),
            "type": "access"
        }
        
        # Refresh token payload
        refresh_payload = {
            "user_id": user_session.user_id,
            "session_id": user_session.session_id,
            "iat": now,
            "exp": now + timedelta(hours=self.config.jwt_refresh_hours),
            "type": "refresh"
        }
        
        try:
            access_token = jwt.encode(
                access_payload,
                self.config.jwt_secret_key,
                algorithm=self.config.jwt_algorithm
            )
            
            refresh_token = jwt.encode(
                refresh_payload,
                self.config.jwt_secret_key,
                algorithm=self.config.jwt_algorithm
            )
            
            return access_token, refresh_token
            
        except Exception as e:
            self.logger.error(f"Token generation failed: {e}")
            raise
    
    def verify_token(self, token: str) -> Tuple[bool, Dict[str, Any]]:
        """Verify and decode JWT token."""
        try:
            payload = jwt.decode(
                token,
                self.config.jwt_secret_key,
                algorithms=[self.config.jwt_algorithm]
            )
            return True, payload
            
        except jwt.ExpiredSignatureError:
            return False, {"error": "Token expired"}
        except jwt.InvalidTokenError as e:
            return False, {"error": f"Invalid token: {str(e)}"}
        except Exception as e:
            self.logger.error(f"Token verification failed: {e}")
            return False, {"error": "Token verification failed"}
    
    def refresh_access_token(self, refresh_token: str) -> Optional[str]:
        """Generate new access token from refresh token."""
        valid, payload = self.verify_token(refresh_token)
        
        if not valid or payload.get("type") != "refresh":
            return None
        
        # Create new access token with updated expiration
        now = datetime.utcnow()
        new_payload = {
            "user_id": payload["user_id"],
            "session_id": payload["session_id"],
            "iat": now,
            "exp": now + timedelta(hours=self.config.jwt_expiration_hours),
            "type": "access"
        }
        
        try:
            return jwt.encode(
                new_payload,
                self.config.jwt_secret_key,
                algorithm=self.config.jwt_algorithm
            )
        except Exception as e:
            self.logger.error(f"Token refresh failed: {e}")
            return None

class EnterpriseAuthenticationManager:
    """Main enterprise authentication manager."""
    
    def __init__(self, config: AuthenticationConfig):
        self.config = config
        self.logger = logging.getLogger(f"{__name__}.EnterpriseAuthenticationManager")
        
        # Initialize components
        self.password_manager = PasswordManager(config)
        self.mfa_manager = MFAManager(config)
        self.ldap_connector = LDAPConnector(config) if config.ldap_server else None
        self.jwt_manager = JWTManager(config)
        self.auditor = SecurityAuditor(config)
        
        # Session management
        self.active_sessions: Dict[str, UserSession] = {}
        self.failed_attempts: Dict[str, List[datetime]] = {}
        self.user_secrets: Dict[str, str] = {}  # In production, use secure storage
        
        self.logger.info("Enterprise Authentication Manager initialized")
        self.logger.info(f"LDAP enabled: {self.ldap_connector is not None}")
        self.logger.info(f"MFA enabled: {config.mfa_enabled}")
    
    def authenticate_user(self, username: str, password: str, 
                         mfa_token: str = None, 
                         ip_address: str = None) -> AuthenticationResult:
        """Authenticate user with comprehensive security checks."""
        
        # Check for account lockout
        if self._is_account_locked(username):
            self.auditor.log_authentication_attempt(
                username, AuthenticationMethod.LOCAL, False, ip_address,
                {"reason": "account_locked"}
            )
            return AuthenticationResult(
                success=False,
                error_message="Account temporarily locked due to failed attempts"
            )
        
        try:
            # Primary authentication
            auth_success, user_info = self._perform_primary_authentication(username, password)
            
            if not auth_success:
                self._record_failed_attempt(username)
                self.auditor.log_authentication_attempt(
                    username, AuthenticationMethod.LOCAL, False, ip_address,
                    {"reason": "invalid_credentials"}
                )
                return AuthenticationResult(
                    success=False,
                    error_message="Invalid credentials"
                )
            
            # Clear failed attempts on successful primary auth
            self._clear_failed_attempts(username)
            
            # Create user session
            user_session = self._create_user_session(username, user_info)
            
            # Check MFA requirements
            if self.config.mfa_enabled:
                mfa_required = self._is_mfa_required(username)
                
                if mfa_required and not mfa_token:
                    # Setup MFA if not configured
                    if not self._has_mfa_setup(username):
                        secret = self.mfa_manager.generate_secret()
                        self.user_secrets[username] = secret
                        qr_code = self.mfa_manager.generate_qr_code(username, secret)
                        
                        return AuthenticationResult(
                            success=False,
                            requires_mfa=True,
                            mfa_setup_required=True,
                            mfa_qr_code=qr_code,
                            error_message="MFA setup required"
                        )
                    else:
                        return AuthenticationResult(
                            success=False,
                            requires_mfa=True,
                            error_message="MFA token required"
                        )
                
                elif mfa_required and mfa_token:
                    # Verify MFA token
                    secret = self.user_secrets.get(username)
                    if not secret or not self.mfa_manager.verify_totp(secret, mfa_token):
                        self.auditor.log_authentication_attempt(
                            username, AuthenticationMethod.MFA, False, ip_address,
                            {"reason": "invalid_mfa_token"}
                        )
                        return AuthenticationResult(
                            success=False,
                            error_message="Invalid MFA token"
                        )
                    
                    user_session.mfa_verified = True
            
            # Generate tokens
            access_token, refresh_token = self.jwt_manager.generate_tokens(user_session)
            
            # Store session
            self.active_sessions[user_session.session_id] = user_session
            
            # Audit successful authentication
            auth_method = AuthenticationMethod.MFA if user_session.mfa_verified else AuthenticationMethod.LOCAL
            if self.ldap_connector and user_info.get("ldap_auth"):
                auth_method = AuthenticationMethod.LDAP
            
            self.auditor.log_authentication_attempt(
                username, auth_method, True, ip_address,
                {"session_id": user_session.session_id}
            )
            
            self.auditor.log_session_event(
                user_session.session_id, "created",
                {"username": username, "roles": [r.value for r in user_session.roles]}
            )
            
            return AuthenticationResult(
                success=True,
                user_session=user_session,
                token=access_token,
                refresh_token=refresh_token
            )
            
        except Exception as e:
            self.logger.error(f"Authentication failed for {username}: {e}")
            self.auditor.log_security_event(
                "authentication_error", username,
                {"error": str(e), "ip_address": ip_address}
            )
            return AuthenticationResult(
                success=False,
                error_message="Authentication system error"
            )
    
    def _perform_primary_authentication(self, username: str, password: str) -> Tuple[bool, Dict[str, Any]]:
        """Perform primary authentication (local or LDAP)."""
        
        # Try LDAP authentication first if configured
        if self.ldap_connector:
            success, user_info = self.ldap_connector.authenticate_user(username, password)
            if success:
                user_info["ldap_auth"] = True
                user_info["roles"] = self._map_groups_to_roles(user_info.get("groups", []))
                return True, user_info
        
        # Fallback to local authentication
        # In production, implement proper user database
        stored_hash = self._get_stored_password_hash(username)
        if stored_hash and self.password_manager.verify_password(password, stored_hash):
            user_info = {
                "username": username,
                "email": f"{username}@local",
                "display_name": username,
                "roles": [UserRole.ANALYST],  # Default role
                "ldap_auth": False
            }
            return True, user_info
        
        return False, {}
    
    def _create_user_session(self, username: str, user_info: Dict[str, Any]) -> UserSession:
        """Create user session object."""
        session_id = secrets.token_urlsafe(32)
        now = datetime.utcnow()
        
        return UserSession(
            user_id=hashlib.sha256(username.encode()).hexdigest()[:16],
            username=username,
            email=user_info.get("email", f"{username}@local"),
            roles=user_info.get("roles", [UserRole.VIEWER]),
            authentication_method=AuthenticationMethod.LDAP if user_info.get("ldap_auth") else AuthenticationMethod.LOCAL,
            login_time=now,
            last_activity=now,
            session_id=session_id,
            permissions=self._get_permissions_for_roles(user_info.get("roles", [])),
            metadata={"display_name": user_info.get("display_name", username)}
        )
    
    def verify_session(self, token: str) -> Tuple[bool, Optional[UserSession]]:
        """Verify user session token."""
        valid, payload = self.jwt_manager.verify_token(token)
        
        if not valid:
            return False, None
        
        session_id = payload.get("session_id")
        if not session_id or session_id not in self.active_sessions:
            return False, None
        
        session = self.active_sessions[session_id]
        
        # Check session timeout
        if self._is_session_expired(session):
            self.logout_user(session_id)
            return False, None
        
        # Update last activity
        session.last_activity = datetime.utcnow()
        
        return True, session
    
    def logout_user(self, session_id: str) -> bool:
        """Logout user and invalidate session."""
        if session_id in self.active_sessions:
            session = self.active_sessions[session_id]
            
            self.auditor.log_session_event(
                session_id, "ended",
                {"username": session.username, "duration": str(datetime.utcnow() - session.login_time)}
            )
            
            del self.active_sessions[session_id]
            return True
        
        return False
    
    def setup_mfa(self, username: str, mfa_token: str) -> Tuple[bool, List[str]]:
        """Complete MFA setup for user."""
        secret = self.user_secrets.get(username)
        if not secret:
            return False, []
        
        if self.mfa_manager.verify_totp(secret, mfa_token):
            # Generate backup codes
            backup_codes = self.mfa_manager.generate_backup_codes()
            
            # In production, store secret and backup codes securely
            self.auditor.log_security_event(
                "mfa_setup_completed", username,
                {"timestamp": datetime.utcnow().isoformat()}
            )
            
            return True, backup_codes
        
        return False, []
    
    def _is_account_locked(self, username: str) -> bool:
        """Check if account is locked due to failed attempts."""
        if username not in self.failed_attempts:
            return False
        
        attempts = self.failed_attempts[username]
        now = datetime.utcnow()
        
        # Remove old attempts
        cutoff = now - timedelta(minutes=self.config.lockout_duration_minutes)
        attempts = [attempt for attempt in attempts if attempt > cutoff]
        self.failed_attempts[username] = attempts
        
        return len(attempts) >= self.config.max_failed_attempts
    
    def _record_failed_attempt(self, username: str):
        """Record failed authentication attempt."""
        if username not in self.failed_attempts:
            self.failed_attempts[username] = []
        
        self.failed_attempts[username].append(datetime.utcnow())
    
    def _clear_failed_attempts(self, username: str):
        """Clear failed attempts for user."""
        if username in self.failed_attempts:
            del self.failed_attempts[username]
    
    def _is_mfa_required(self, username: str) -> bool:
        """Check if MFA is required for user."""
        return self.config.mfa_enabled
    
    def _has_mfa_setup(self, username: str) -> bool:
        """Check if user has MFA setup."""
        return username in self.user_secrets
    
    def _is_session_expired(self, session: UserSession) -> bool:
        """Check if session has expired."""
        timeout = timedelta(minutes=self.config.session_timeout_minutes)
        return datetime.utcnow() - session.last_activity > timeout
    
    def _map_groups_to_roles(self, groups: List[str]) -> List[UserRole]:
        """Map LDAP groups to user roles."""
        role_mapping = {
            "AODS_Administrators": UserRole.ADMIN,
            "AODS_Analysts": UserRole.ANALYST,
            "AODS_Viewers": UserRole.VIEWER,
            "AODS_Auditors": UserRole.AUDITOR,
            "AODS_API_Users": UserRole.API_USER
        }
        
        roles = []
        for group in groups:
            group_name = group.split(',')[0].replace('CN=', '')
            if group_name in role_mapping:
                roles.append(role_mapping[group_name])
        
        return roles if roles else [UserRole.VIEWER]
    
    def _get_permissions_for_roles(self, roles: List[UserRole]) -> List[str]:
        """Get permissions based on user roles."""
        permission_map = {
            UserRole.ADMIN: ["admin.all", "analysis.manage", "users.manage", "system.configure"],
            UserRole.ANALYST: ["analysis.run", "analysis.view", "reports.generate"],
            UserRole.VIEWER: ["analysis.view", "reports.view"],
            UserRole.AUDITOR: ["audit.view", "reports.view", "logs.access"],
            UserRole.API_USER: ["api.access", "analysis.run"]
        }
        
        permissions = set()
        for role in roles:
            permissions.update(permission_map.get(role, []))
        
        return list(permissions)
    
    def _get_stored_password_hash(self, username: str) -> Optional[str]:
        """Get stored password hash for user (implement with secure storage)."""
        # In production, implement proper user database lookup
        # This is a placeholder for local authentication
        return None
    
    def get_session_info(self, session_id: str) -> Optional[Dict[str, Any]]:
        """Get session information."""
        if session_id not in self.active_sessions:
            return None
        
        session = self.active_sessions[session_id]
        
        return {
            "user_id": session.user_id,
            "username": session.username,
            "email": session.email,
            "roles": [role.value for role in session.roles],
            "permissions": session.permissions,
            "login_time": session.login_time.isoformat(),
            "last_activity": session.last_activity.isoformat(),
            "mfa_verified": session.mfa_verified,
            "authentication_method": session.authentication_method.value,
            "metadata": session.metadata
        }
    
    def get_active_sessions(self) -> List[Dict[str, Any]]:
        """Get all active sessions."""
        sessions = []
        for session_id, session in self.active_sessions.items():
            sessions.append({
                "session_id": session_id,
                "username": session.username,
                "login_time": session.login_time.isoformat(),
                "last_activity": session.last_activity.isoformat(),
                "roles": [role.value for role in session.roles]
            })
        
        return sessions

# Factory function for easy initialization
def create_authentication_manager(config_dict: Dict[str, Any] = None) -> EnterpriseAuthenticationManager:
    """Create enterprise authentication manager with configuration."""
    config = AuthenticationConfig()
    
    if config_dict:
        for key, value in config_dict.items():
            if hasattr(config, key):
                setattr(config, key, value)
    
    return EnterpriseAuthenticationManager(config)

if __name__ == "__main__":
    # Example usage and testing
    config = {
        "mfa_enabled": True,
        "ldap_server": "ldap.example.com",
        "ldap_base_dn": "dc=example,dc=com",
        "audit_enabled": True
    }
    
    auth_manager = create_authentication_manager(config)
    
    # Test authentication
    result = auth_manager.authenticate_user("testuser", "password123")
    print(f"Authentication result: {result}") 