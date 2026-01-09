from google.protobuf import timestamp_pb2 as _timestamp_pb2
from google.protobuf.internal import containers as _containers
from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from typing import ClassVar as _ClassVar, Iterable as _Iterable, Mapping as _Mapping, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class ResourceType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    RESOURCE_TYPE_UNSPECIFIED: _ClassVar[ResourceType]
    RESOURCE_TYPE_DATABASE: _ClassVar[ResourceType]
    RESOURCE_TYPE_CACHE: _ClassVar[ResourceType]

class Engine(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    ENGINE_UNSPECIFIED: _ClassVar[Engine]
    ENGINE_POSTGRESQL: _ClassVar[Engine]
    ENGINE_MYSQL: _ClassVar[Engine]
    ENGINE_MARIADB: _ClassVar[Engine]
    ENGINE_REDIS: _ClassVar[Engine]
    ENGINE_MEMCACHED: _ClassVar[Engine]
    ENGINE_MONGODB: _ClassVar[Engine]
    ENGINE_SQLSERVER: _ClassVar[Engine]

class ResourceStatus(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    RESOURCE_STATUS_UNSPECIFIED: _ClassVar[ResourceStatus]
    RESOURCE_STATUS_PROVISIONING: _ClassVar[ResourceStatus]
    RESOURCE_STATUS_AVAILABLE: _ClassVar[ResourceStatus]
    RESOURCE_STATUS_MODIFYING: _ClassVar[ResourceStatus]
    RESOURCE_STATUS_DELETING: _ClassVar[ResourceStatus]
    RESOURCE_STATUS_DELETED: _ClassVar[ResourceStatus]
    RESOURCE_STATUS_FAILED: _ClassVar[ResourceStatus]

class ProviderType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    PROVIDER_TYPE_UNSPECIFIED: _ClassVar[ProviderType]
    PROVIDER_TYPE_KUBERNETES: _ClassVar[ProviderType]
    PROVIDER_TYPE_AWS: _ClassVar[ProviderType]
    PROVIDER_TYPE_GCP: _ClassVar[ProviderType]
    PROVIDER_TYPE_AZURE: _ClassVar[ProviderType]
    PROVIDER_TYPE_VULTR: _ClassVar[ProviderType]

class TLSMode(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    TLS_MODE_UNSPECIFIED: _ClassVar[TLSMode]
    TLS_MODE_DISABLED: _ClassVar[TLSMode]
    TLS_MODE_OPTIONAL: _ClassVar[TLSMode]
    TLS_MODE_REQUIRED: _ClassVar[TLSMode]

class CredentialType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    CREDENTIAL_TYPE_UNSPECIFIED: _ClassVar[CredentialType]
    CREDENTIAL_TYPE_PASSWORD: _ClassVar[CredentialType]
    CREDENTIAL_TYPE_IAM_ROLE: _ClassVar[CredentialType]
    CREDENTIAL_TYPE_JWT: _ClassVar[CredentialType]
    CREDENTIAL_TYPE_MTLS: _ClassVar[CredentialType]

class DeploymentModel(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    DEPLOYMENT_MODEL_UNSPECIFIED: _ClassVar[DeploymentModel]
    DEPLOYMENT_MODEL_SHARED: _ClassVar[DeploymentModel]
    DEPLOYMENT_MODEL_SEPARATE: _ClassVar[DeploymentModel]

class LicenseTier(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    LICENSE_TIER_UNSPECIFIED: _ClassVar[LicenseTier]
    LICENSE_TIER_FREE: _ClassVar[LicenseTier]
    LICENSE_TIER_PROFESSIONAL: _ClassVar[LicenseTier]
    LICENSE_TIER_ENTERPRISE: _ClassVar[LicenseTier]

class EventType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    EVENT_TYPE_UNSPECIFIED: _ClassVar[EventType]
    EVENT_TYPE_RESOURCE_CREATED: _ClassVar[EventType]
    EVENT_TYPE_RESOURCE_UPDATED: _ClassVar[EventType]
    EVENT_TYPE_RESOURCE_DELETED: _ClassVar[EventType]
    EVENT_TYPE_CREDENTIAL_ROTATED: _ClassVar[EventType]
    EVENT_TYPE_HEALTH_CHECK: _ClassVar[EventType]
RESOURCE_TYPE_UNSPECIFIED: ResourceType
RESOURCE_TYPE_DATABASE: ResourceType
RESOURCE_TYPE_CACHE: ResourceType
ENGINE_UNSPECIFIED: Engine
ENGINE_POSTGRESQL: Engine
ENGINE_MYSQL: Engine
ENGINE_MARIADB: Engine
ENGINE_REDIS: Engine
ENGINE_MEMCACHED: Engine
ENGINE_MONGODB: Engine
ENGINE_SQLSERVER: Engine
RESOURCE_STATUS_UNSPECIFIED: ResourceStatus
RESOURCE_STATUS_PROVISIONING: ResourceStatus
RESOURCE_STATUS_AVAILABLE: ResourceStatus
RESOURCE_STATUS_MODIFYING: ResourceStatus
RESOURCE_STATUS_DELETING: ResourceStatus
RESOURCE_STATUS_DELETED: ResourceStatus
RESOURCE_STATUS_FAILED: ResourceStatus
PROVIDER_TYPE_UNSPECIFIED: ProviderType
PROVIDER_TYPE_KUBERNETES: ProviderType
PROVIDER_TYPE_AWS: ProviderType
PROVIDER_TYPE_GCP: ProviderType
PROVIDER_TYPE_AZURE: ProviderType
PROVIDER_TYPE_VULTR: ProviderType
TLS_MODE_UNSPECIFIED: TLSMode
TLS_MODE_DISABLED: TLSMode
TLS_MODE_OPTIONAL: TLSMode
TLS_MODE_REQUIRED: TLSMode
CREDENTIAL_TYPE_UNSPECIFIED: CredentialType
CREDENTIAL_TYPE_PASSWORD: CredentialType
CREDENTIAL_TYPE_IAM_ROLE: CredentialType
CREDENTIAL_TYPE_JWT: CredentialType
CREDENTIAL_TYPE_MTLS: CredentialType
DEPLOYMENT_MODEL_UNSPECIFIED: DeploymentModel
DEPLOYMENT_MODEL_SHARED: DeploymentModel
DEPLOYMENT_MODEL_SEPARATE: DeploymentModel
LICENSE_TIER_UNSPECIFIED: LicenseTier
LICENSE_TIER_FREE: LicenseTier
LICENSE_TIER_PROFESSIONAL: LicenseTier
LICENSE_TIER_ENTERPRISE: LicenseTier
EVENT_TYPE_UNSPECIFIED: EventType
EVENT_TYPE_RESOURCE_CREATED: EventType
EVENT_TYPE_RESOURCE_UPDATED: EventType
EVENT_TYPE_RESOURCE_DELETED: EventType
EVENT_TYPE_CREDENTIAL_ROTATED: EventType
EVENT_TYPE_HEALTH_CHECK: EventType

class Resource(_message.Message):
    __slots__ = ("id", "name", "resource_type", "engine", "provider_id", "application_id", "endpoint", "port", "database_name", "instance_class", "storage_size_gb", "multi_az", "replicas", "tls_mode", "status", "status_message", "tags", "elder_entity_id", "created_at", "updated_at")
    class TagsEntry(_message.Message):
        __slots__ = ("key", "value")
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: str
        value: str
        def __init__(self, key: _Optional[str] = ..., value: _Optional[str] = ...) -> None: ...
    ID_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    RESOURCE_TYPE_FIELD_NUMBER: _ClassVar[int]
    ENGINE_FIELD_NUMBER: _ClassVar[int]
    PROVIDER_ID_FIELD_NUMBER: _ClassVar[int]
    APPLICATION_ID_FIELD_NUMBER: _ClassVar[int]
    ENDPOINT_FIELD_NUMBER: _ClassVar[int]
    PORT_FIELD_NUMBER: _ClassVar[int]
    DATABASE_NAME_FIELD_NUMBER: _ClassVar[int]
    INSTANCE_CLASS_FIELD_NUMBER: _ClassVar[int]
    STORAGE_SIZE_GB_FIELD_NUMBER: _ClassVar[int]
    MULTI_AZ_FIELD_NUMBER: _ClassVar[int]
    REPLICAS_FIELD_NUMBER: _ClassVar[int]
    TLS_MODE_FIELD_NUMBER: _ClassVar[int]
    STATUS_FIELD_NUMBER: _ClassVar[int]
    STATUS_MESSAGE_FIELD_NUMBER: _ClassVar[int]
    TAGS_FIELD_NUMBER: _ClassVar[int]
    ELDER_ENTITY_ID_FIELD_NUMBER: _ClassVar[int]
    CREATED_AT_FIELD_NUMBER: _ClassVar[int]
    UPDATED_AT_FIELD_NUMBER: _ClassVar[int]
    id: int
    name: str
    resource_type: ResourceType
    engine: Engine
    provider_id: int
    application_id: int
    endpoint: str
    port: int
    database_name: str
    instance_class: str
    storage_size_gb: int
    multi_az: bool
    replicas: int
    tls_mode: TLSMode
    status: ResourceStatus
    status_message: str
    tags: _containers.ScalarMap[str, str]
    elder_entity_id: str
    created_at: _timestamp_pb2.Timestamp
    updated_at: _timestamp_pb2.Timestamp
    def __init__(self, id: _Optional[int] = ..., name: _Optional[str] = ..., resource_type: _Optional[_Union[ResourceType, str]] = ..., engine: _Optional[_Union[Engine, str]] = ..., provider_id: _Optional[int] = ..., application_id: _Optional[int] = ..., endpoint: _Optional[str] = ..., port: _Optional[int] = ..., database_name: _Optional[str] = ..., instance_class: _Optional[str] = ..., storage_size_gb: _Optional[int] = ..., multi_az: bool = ..., replicas: _Optional[int] = ..., tls_mode: _Optional[_Union[TLSMode, str]] = ..., status: _Optional[_Union[ResourceStatus, str]] = ..., status_message: _Optional[str] = ..., tags: _Optional[_Mapping[str, str]] = ..., elder_entity_id: _Optional[str] = ..., created_at: _Optional[_Union[_timestamp_pb2.Timestamp, _Mapping]] = ..., updated_at: _Optional[_Union[_timestamp_pb2.Timestamp, _Mapping]] = ...) -> None: ...

class Application(_message.Message):
    __slots__ = ("id", "name", "description", "deployment_model", "elder_entity_id", "elder_service_id", "tags", "created_at", "updated_at")
    class TagsEntry(_message.Message):
        __slots__ = ("key", "value")
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: str
        value: str
        def __init__(self, key: _Optional[str] = ..., value: _Optional[str] = ...) -> None: ...
    ID_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    DESCRIPTION_FIELD_NUMBER: _ClassVar[int]
    DEPLOYMENT_MODEL_FIELD_NUMBER: _ClassVar[int]
    ELDER_ENTITY_ID_FIELD_NUMBER: _ClassVar[int]
    ELDER_SERVICE_ID_FIELD_NUMBER: _ClassVar[int]
    TAGS_FIELD_NUMBER: _ClassVar[int]
    CREATED_AT_FIELD_NUMBER: _ClassVar[int]
    UPDATED_AT_FIELD_NUMBER: _ClassVar[int]
    id: int
    name: str
    description: str
    deployment_model: DeploymentModel
    elder_entity_id: str
    elder_service_id: str
    tags: _containers.ScalarMap[str, str]
    created_at: _timestamp_pb2.Timestamp
    updated_at: _timestamp_pb2.Timestamp
    def __init__(self, id: _Optional[int] = ..., name: _Optional[str] = ..., description: _Optional[str] = ..., deployment_model: _Optional[_Union[DeploymentModel, str]] = ..., elder_entity_id: _Optional[str] = ..., elder_service_id: _Optional[str] = ..., tags: _Optional[_Mapping[str, str]] = ..., created_at: _Optional[_Union[_timestamp_pb2.Timestamp, _Mapping]] = ..., updated_at: _Optional[_Union[_timestamp_pb2.Timestamp, _Mapping]] = ...) -> None: ...

class Credential(_message.Message):
    __slots__ = ("id", "resource_id", "application_id", "credential_type", "username", "iam_role_arn", "iam_policy", "jwt_subject", "jwt_claims", "permissions", "expires_at", "auto_rotate", "rotation_interval_days", "last_rotated_at", "next_rotation_at", "created_at", "updated_at")
    class JwtClaimsEntry(_message.Message):
        __slots__ = ("key", "value")
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: str
        value: str
        def __init__(self, key: _Optional[str] = ..., value: _Optional[str] = ...) -> None: ...
    ID_FIELD_NUMBER: _ClassVar[int]
    RESOURCE_ID_FIELD_NUMBER: _ClassVar[int]
    APPLICATION_ID_FIELD_NUMBER: _ClassVar[int]
    CREDENTIAL_TYPE_FIELD_NUMBER: _ClassVar[int]
    USERNAME_FIELD_NUMBER: _ClassVar[int]
    IAM_ROLE_ARN_FIELD_NUMBER: _ClassVar[int]
    IAM_POLICY_FIELD_NUMBER: _ClassVar[int]
    JWT_SUBJECT_FIELD_NUMBER: _ClassVar[int]
    JWT_CLAIMS_FIELD_NUMBER: _ClassVar[int]
    PERMISSIONS_FIELD_NUMBER: _ClassVar[int]
    EXPIRES_AT_FIELD_NUMBER: _ClassVar[int]
    AUTO_ROTATE_FIELD_NUMBER: _ClassVar[int]
    ROTATION_INTERVAL_DAYS_FIELD_NUMBER: _ClassVar[int]
    LAST_ROTATED_AT_FIELD_NUMBER: _ClassVar[int]
    NEXT_ROTATION_AT_FIELD_NUMBER: _ClassVar[int]
    CREATED_AT_FIELD_NUMBER: _ClassVar[int]
    UPDATED_AT_FIELD_NUMBER: _ClassVar[int]
    id: int
    resource_id: int
    application_id: int
    credential_type: CredentialType
    username: str
    iam_role_arn: str
    iam_policy: str
    jwt_subject: str
    jwt_claims: _containers.ScalarMap[str, str]
    permissions: _containers.RepeatedScalarFieldContainer[str]
    expires_at: _timestamp_pb2.Timestamp
    auto_rotate: bool
    rotation_interval_days: int
    last_rotated_at: _timestamp_pb2.Timestamp
    next_rotation_at: _timestamp_pb2.Timestamp
    created_at: _timestamp_pb2.Timestamp
    updated_at: _timestamp_pb2.Timestamp
    def __init__(self, id: _Optional[int] = ..., resource_id: _Optional[int] = ..., application_id: _Optional[int] = ..., credential_type: _Optional[_Union[CredentialType, str]] = ..., username: _Optional[str] = ..., iam_role_arn: _Optional[str] = ..., iam_policy: _Optional[str] = ..., jwt_subject: _Optional[str] = ..., jwt_claims: _Optional[_Mapping[str, str]] = ..., permissions: _Optional[_Iterable[str]] = ..., expires_at: _Optional[_Union[_timestamp_pb2.Timestamp, _Mapping]] = ..., auto_rotate: bool = ..., rotation_interval_days: _Optional[int] = ..., last_rotated_at: _Optional[_Union[_timestamp_pb2.Timestamp, _Mapping]] = ..., next_rotation_at: _Optional[_Union[_timestamp_pb2.Timestamp, _Mapping]] = ..., created_at: _Optional[_Union[_timestamp_pb2.Timestamp, _Mapping]] = ..., updated_at: _Optional[_Union[_timestamp_pb2.Timestamp, _Mapping]] = ...) -> None: ...

class Provider(_message.Message):
    __slots__ = ("id", "name", "provider_type", "configuration", "credentials_secret_name", "enabled", "last_test_at", "last_test_success", "last_test_message", "created_at", "updated_at")
    ID_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    PROVIDER_TYPE_FIELD_NUMBER: _ClassVar[int]
    CONFIGURATION_FIELD_NUMBER: _ClassVar[int]
    CREDENTIALS_SECRET_NAME_FIELD_NUMBER: _ClassVar[int]
    ENABLED_FIELD_NUMBER: _ClassVar[int]
    LAST_TEST_AT_FIELD_NUMBER: _ClassVar[int]
    LAST_TEST_SUCCESS_FIELD_NUMBER: _ClassVar[int]
    LAST_TEST_MESSAGE_FIELD_NUMBER: _ClassVar[int]
    CREATED_AT_FIELD_NUMBER: _ClassVar[int]
    UPDATED_AT_FIELD_NUMBER: _ClassVar[int]
    id: int
    name: str
    provider_type: ProviderType
    configuration: str
    credentials_secret_name: str
    enabled: bool
    last_test_at: _timestamp_pb2.Timestamp
    last_test_success: bool
    last_test_message: str
    created_at: _timestamp_pb2.Timestamp
    updated_at: _timestamp_pb2.Timestamp
    def __init__(self, id: _Optional[int] = ..., name: _Optional[str] = ..., provider_type: _Optional[_Union[ProviderType, str]] = ..., configuration: _Optional[str] = ..., credentials_secret_name: _Optional[str] = ..., enabled: bool = ..., last_test_at: _Optional[_Union[_timestamp_pb2.Timestamp, _Mapping]] = ..., last_test_success: bool = ..., last_test_message: _Optional[str] = ..., created_at: _Optional[_Union[_timestamp_pb2.Timestamp, _Mapping]] = ..., updated_at: _Optional[_Union[_timestamp_pb2.Timestamp, _Mapping]] = ...) -> None: ...

class Pagination(_message.Message):
    __slots__ = ("page", "page_size", "total", "total_pages")
    PAGE_FIELD_NUMBER: _ClassVar[int]
    PAGE_SIZE_FIELD_NUMBER: _ClassVar[int]
    TOTAL_FIELD_NUMBER: _ClassVar[int]
    TOTAL_PAGES_FIELD_NUMBER: _ClassVar[int]
    page: int
    page_size: int
    total: int
    total_pages: int
    def __init__(self, page: _Optional[int] = ..., page_size: _Optional[int] = ..., total: _Optional[int] = ..., total_pages: _Optional[int] = ...) -> None: ...

class Event(_message.Message):
    __slots__ = ("event_type", "resource_id", "message", "timestamp", "metadata")
    class MetadataEntry(_message.Message):
        __slots__ = ("key", "value")
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: str
        value: str
        def __init__(self, key: _Optional[str] = ..., value: _Optional[str] = ...) -> None: ...
    EVENT_TYPE_FIELD_NUMBER: _ClassVar[int]
    RESOURCE_ID_FIELD_NUMBER: _ClassVar[int]
    MESSAGE_FIELD_NUMBER: _ClassVar[int]
    TIMESTAMP_FIELD_NUMBER: _ClassVar[int]
    METADATA_FIELD_NUMBER: _ClassVar[int]
    event_type: EventType
    resource_id: int
    message: str
    timestamp: _timestamp_pb2.Timestamp
    metadata: _containers.ScalarMap[str, str]
    def __init__(self, event_type: _Optional[_Union[EventType, str]] = ..., resource_id: _Optional[int] = ..., message: _Optional[str] = ..., timestamp: _Optional[_Union[_timestamp_pb2.Timestamp, _Mapping]] = ..., metadata: _Optional[_Mapping[str, str]] = ...) -> None: ...
