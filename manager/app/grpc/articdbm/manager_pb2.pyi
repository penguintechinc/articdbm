from google.protobuf import timestamp_pb2 as _timestamp_pb2
from google.protobuf import empty_pb2 as _empty_pb2
from articdbm import types_pb2 as _types_pb2
from google.protobuf.internal import containers as _containers
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from typing import ClassVar as _ClassVar, Iterable as _Iterable, Mapping as _Mapping, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class GetDashboardStatsRequest(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class GetDashboardStatsResponse(_message.Message):
    __slots__ = ("total_resources", "active_resources", "total_applications", "total_credentials", "license_tier", "resource_limit", "resources_by_type", "resources_by_status")
    class ResourcesByTypeEntry(_message.Message):
        __slots__ = ("key", "value")
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: str
        value: int
        def __init__(self, key: _Optional[str] = ..., value: _Optional[int] = ...) -> None: ...
    class ResourcesByStatusEntry(_message.Message):
        __slots__ = ("key", "value")
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: str
        value: int
        def __init__(self, key: _Optional[str] = ..., value: _Optional[int] = ...) -> None: ...
    TOTAL_RESOURCES_FIELD_NUMBER: _ClassVar[int]
    ACTIVE_RESOURCES_FIELD_NUMBER: _ClassVar[int]
    TOTAL_APPLICATIONS_FIELD_NUMBER: _ClassVar[int]
    TOTAL_CREDENTIALS_FIELD_NUMBER: _ClassVar[int]
    LICENSE_TIER_FIELD_NUMBER: _ClassVar[int]
    RESOURCE_LIMIT_FIELD_NUMBER: _ClassVar[int]
    RESOURCES_BY_TYPE_FIELD_NUMBER: _ClassVar[int]
    RESOURCES_BY_STATUS_FIELD_NUMBER: _ClassVar[int]
    total_resources: int
    active_resources: int
    total_applications: int
    total_credentials: int
    license_tier: _types_pb2.LicenseTier
    resource_limit: int
    resources_by_type: _containers.ScalarMap[str, int]
    resources_by_status: _containers.ScalarMap[str, int]
    def __init__(self, total_resources: _Optional[int] = ..., active_resources: _Optional[int] = ..., total_applications: _Optional[int] = ..., total_credentials: _Optional[int] = ..., license_tier: _Optional[_Union[_types_pb2.LicenseTier, str]] = ..., resource_limit: _Optional[int] = ..., resources_by_type: _Optional[_Mapping[str, int]] = ..., resources_by_status: _Optional[_Mapping[str, int]] = ...) -> None: ...

class StreamEventsRequest(_message.Message):
    __slots__ = ("event_types",)
    EVENT_TYPES_FIELD_NUMBER: _ClassVar[int]
    event_types: _containers.RepeatedScalarFieldContainer[_types_pb2.EventType]
    def __init__(self, event_types: _Optional[_Iterable[_Union[_types_pb2.EventType, str]]] = ...) -> None: ...

class ListResourcesRequest(_message.Message):
    __slots__ = ("page", "page_size", "resource_type", "status", "application_id")
    PAGE_FIELD_NUMBER: _ClassVar[int]
    PAGE_SIZE_FIELD_NUMBER: _ClassVar[int]
    RESOURCE_TYPE_FIELD_NUMBER: _ClassVar[int]
    STATUS_FIELD_NUMBER: _ClassVar[int]
    APPLICATION_ID_FIELD_NUMBER: _ClassVar[int]
    page: int
    page_size: int
    resource_type: _types_pb2.ResourceType
    status: _types_pb2.ResourceStatus
    application_id: int
    def __init__(self, page: _Optional[int] = ..., page_size: _Optional[int] = ..., resource_type: _Optional[_Union[_types_pb2.ResourceType, str]] = ..., status: _Optional[_Union[_types_pb2.ResourceStatus, str]] = ..., application_id: _Optional[int] = ...) -> None: ...

class ListResourcesResponse(_message.Message):
    __slots__ = ("resources", "pagination")
    RESOURCES_FIELD_NUMBER: _ClassVar[int]
    PAGINATION_FIELD_NUMBER: _ClassVar[int]
    resources: _containers.RepeatedCompositeFieldContainer[_types_pb2.Resource]
    pagination: _types_pb2.Pagination
    def __init__(self, resources: _Optional[_Iterable[_Union[_types_pb2.Resource, _Mapping]]] = ..., pagination: _Optional[_Union[_types_pb2.Pagination, _Mapping]] = ...) -> None: ...

class GetResourceRequest(_message.Message):
    __slots__ = ("id",)
    ID_FIELD_NUMBER: _ClassVar[int]
    id: int
    def __init__(self, id: _Optional[int] = ...) -> None: ...

class GetResourceResponse(_message.Message):
    __slots__ = ("resource",)
    RESOURCE_FIELD_NUMBER: _ClassVar[int]
    resource: _types_pb2.Resource
    def __init__(self, resource: _Optional[_Union[_types_pb2.Resource, _Mapping]] = ...) -> None: ...

class CreateResourceRequest(_message.Message):
    __slots__ = ("name", "resource_type", "engine", "provider_id", "application_id", "database_name", "instance_class", "storage_size_gb", "multi_az", "replicas", "tls_mode", "tags")
    class TagsEntry(_message.Message):
        __slots__ = ("key", "value")
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: str
        value: str
        def __init__(self, key: _Optional[str] = ..., value: _Optional[str] = ...) -> None: ...
    NAME_FIELD_NUMBER: _ClassVar[int]
    RESOURCE_TYPE_FIELD_NUMBER: _ClassVar[int]
    ENGINE_FIELD_NUMBER: _ClassVar[int]
    PROVIDER_ID_FIELD_NUMBER: _ClassVar[int]
    APPLICATION_ID_FIELD_NUMBER: _ClassVar[int]
    DATABASE_NAME_FIELD_NUMBER: _ClassVar[int]
    INSTANCE_CLASS_FIELD_NUMBER: _ClassVar[int]
    STORAGE_SIZE_GB_FIELD_NUMBER: _ClassVar[int]
    MULTI_AZ_FIELD_NUMBER: _ClassVar[int]
    REPLICAS_FIELD_NUMBER: _ClassVar[int]
    TLS_MODE_FIELD_NUMBER: _ClassVar[int]
    TAGS_FIELD_NUMBER: _ClassVar[int]
    name: str
    resource_type: _types_pb2.ResourceType
    engine: _types_pb2.Engine
    provider_id: int
    application_id: int
    database_name: str
    instance_class: str
    storage_size_gb: int
    multi_az: bool
    replicas: int
    tls_mode: _types_pb2.TLSMode
    tags: _containers.ScalarMap[str, str]
    def __init__(self, name: _Optional[str] = ..., resource_type: _Optional[_Union[_types_pb2.ResourceType, str]] = ..., engine: _Optional[_Union[_types_pb2.Engine, str]] = ..., provider_id: _Optional[int] = ..., application_id: _Optional[int] = ..., database_name: _Optional[str] = ..., instance_class: _Optional[str] = ..., storage_size_gb: _Optional[int] = ..., multi_az: bool = ..., replicas: _Optional[int] = ..., tls_mode: _Optional[_Union[_types_pb2.TLSMode, str]] = ..., tags: _Optional[_Mapping[str, str]] = ...) -> None: ...

class CreateResourceResponse(_message.Message):
    __slots__ = ("resource",)
    RESOURCE_FIELD_NUMBER: _ClassVar[int]
    resource: _types_pb2.Resource
    def __init__(self, resource: _Optional[_Union[_types_pb2.Resource, _Mapping]] = ...) -> None: ...

class UpdateResourceRequest(_message.Message):
    __slots__ = ("id", "name", "instance_class", "storage_size_gb", "multi_az", "replicas", "tls_mode", "tags")
    class TagsEntry(_message.Message):
        __slots__ = ("key", "value")
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: str
        value: str
        def __init__(self, key: _Optional[str] = ..., value: _Optional[str] = ...) -> None: ...
    ID_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    INSTANCE_CLASS_FIELD_NUMBER: _ClassVar[int]
    STORAGE_SIZE_GB_FIELD_NUMBER: _ClassVar[int]
    MULTI_AZ_FIELD_NUMBER: _ClassVar[int]
    REPLICAS_FIELD_NUMBER: _ClassVar[int]
    TLS_MODE_FIELD_NUMBER: _ClassVar[int]
    TAGS_FIELD_NUMBER: _ClassVar[int]
    id: int
    name: str
    instance_class: str
    storage_size_gb: int
    multi_az: bool
    replicas: int
    tls_mode: _types_pb2.TLSMode
    tags: _containers.ScalarMap[str, str]
    def __init__(self, id: _Optional[int] = ..., name: _Optional[str] = ..., instance_class: _Optional[str] = ..., storage_size_gb: _Optional[int] = ..., multi_az: bool = ..., replicas: _Optional[int] = ..., tls_mode: _Optional[_Union[_types_pb2.TLSMode, str]] = ..., tags: _Optional[_Mapping[str, str]] = ...) -> None: ...

class UpdateResourceResponse(_message.Message):
    __slots__ = ("resource",)
    RESOURCE_FIELD_NUMBER: _ClassVar[int]
    resource: _types_pb2.Resource
    def __init__(self, resource: _Optional[_Union[_types_pb2.Resource, _Mapping]] = ...) -> None: ...

class DeleteResourceRequest(_message.Message):
    __slots__ = ("id",)
    ID_FIELD_NUMBER: _ClassVar[int]
    id: int
    def __init__(self, id: _Optional[int] = ...) -> None: ...

class DeleteResourceResponse(_message.Message):
    __slots__ = ("success",)
    SUCCESS_FIELD_NUMBER: _ClassVar[int]
    success: bool
    def __init__(self, success: bool = ...) -> None: ...

class ScaleResourceRequest(_message.Message):
    __slots__ = ("id", "instance_class", "replicas")
    ID_FIELD_NUMBER: _ClassVar[int]
    INSTANCE_CLASS_FIELD_NUMBER: _ClassVar[int]
    REPLICAS_FIELD_NUMBER: _ClassVar[int]
    id: int
    instance_class: str
    replicas: int
    def __init__(self, id: _Optional[int] = ..., instance_class: _Optional[str] = ..., replicas: _Optional[int] = ...) -> None: ...

class ScaleResourceResponse(_message.Message):
    __slots__ = ("resource",)
    RESOURCE_FIELD_NUMBER: _ClassVar[int]
    resource: _types_pb2.Resource
    def __init__(self, resource: _Optional[_Union[_types_pb2.Resource, _Mapping]] = ...) -> None: ...

class GetResourceMetricsRequest(_message.Message):
    __slots__ = ("id", "start_time", "end_time")
    ID_FIELD_NUMBER: _ClassVar[int]
    START_TIME_FIELD_NUMBER: _ClassVar[int]
    END_TIME_FIELD_NUMBER: _ClassVar[int]
    id: int
    start_time: _timestamp_pb2.Timestamp
    end_time: _timestamp_pb2.Timestamp
    def __init__(self, id: _Optional[int] = ..., start_time: _Optional[_Union[_timestamp_pb2.Timestamp, _Mapping]] = ..., end_time: _Optional[_Union[_timestamp_pb2.Timestamp, _Mapping]] = ...) -> None: ...

class Metric(_message.Message):
    __slots__ = ("timestamp", "value")
    TIMESTAMP_FIELD_NUMBER: _ClassVar[int]
    VALUE_FIELD_NUMBER: _ClassVar[int]
    timestamp: _timestamp_pb2.Timestamp
    value: float
    def __init__(self, timestamp: _Optional[_Union[_timestamp_pb2.Timestamp, _Mapping]] = ..., value: _Optional[float] = ...) -> None: ...

class GetResourceMetricsResponse(_message.Message):
    __slots__ = ("cpu_utilization", "memory_utilization", "connections", "storage_used")
    CPU_UTILIZATION_FIELD_NUMBER: _ClassVar[int]
    MEMORY_UTILIZATION_FIELD_NUMBER: _ClassVar[int]
    CONNECTIONS_FIELD_NUMBER: _ClassVar[int]
    STORAGE_USED_FIELD_NUMBER: _ClassVar[int]
    cpu_utilization: _containers.RepeatedCompositeFieldContainer[Metric]
    memory_utilization: _containers.RepeatedCompositeFieldContainer[Metric]
    connections: _containers.RepeatedCompositeFieldContainer[Metric]
    storage_used: _containers.RepeatedCompositeFieldContainer[Metric]
    def __init__(self, cpu_utilization: _Optional[_Iterable[_Union[Metric, _Mapping]]] = ..., memory_utilization: _Optional[_Iterable[_Union[Metric, _Mapping]]] = ..., connections: _Optional[_Iterable[_Union[Metric, _Mapping]]] = ..., storage_used: _Optional[_Iterable[_Union[Metric, _Mapping]]] = ...) -> None: ...

class ListApplicationsRequest(_message.Message):
    __slots__ = ("page", "page_size")
    PAGE_FIELD_NUMBER: _ClassVar[int]
    PAGE_SIZE_FIELD_NUMBER: _ClassVar[int]
    page: int
    page_size: int
    def __init__(self, page: _Optional[int] = ..., page_size: _Optional[int] = ...) -> None: ...

class ListApplicationsResponse(_message.Message):
    __slots__ = ("applications", "pagination")
    APPLICATIONS_FIELD_NUMBER: _ClassVar[int]
    PAGINATION_FIELD_NUMBER: _ClassVar[int]
    applications: _containers.RepeatedCompositeFieldContainer[_types_pb2.Application]
    pagination: _types_pb2.Pagination
    def __init__(self, applications: _Optional[_Iterable[_Union[_types_pb2.Application, _Mapping]]] = ..., pagination: _Optional[_Union[_types_pb2.Pagination, _Mapping]] = ...) -> None: ...

class GetApplicationRequest(_message.Message):
    __slots__ = ("id",)
    ID_FIELD_NUMBER: _ClassVar[int]
    id: int
    def __init__(self, id: _Optional[int] = ...) -> None: ...

class GetApplicationResponse(_message.Message):
    __slots__ = ("application",)
    APPLICATION_FIELD_NUMBER: _ClassVar[int]
    application: _types_pb2.Application
    def __init__(self, application: _Optional[_Union[_types_pb2.Application, _Mapping]] = ...) -> None: ...

class CreateApplicationRequest(_message.Message):
    __slots__ = ("name", "description", "deployment_model", "tags")
    class TagsEntry(_message.Message):
        __slots__ = ("key", "value")
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: str
        value: str
        def __init__(self, key: _Optional[str] = ..., value: _Optional[str] = ...) -> None: ...
    NAME_FIELD_NUMBER: _ClassVar[int]
    DESCRIPTION_FIELD_NUMBER: _ClassVar[int]
    DEPLOYMENT_MODEL_FIELD_NUMBER: _ClassVar[int]
    TAGS_FIELD_NUMBER: _ClassVar[int]
    name: str
    description: str
    deployment_model: _types_pb2.DeploymentModel
    tags: _containers.ScalarMap[str, str]
    def __init__(self, name: _Optional[str] = ..., description: _Optional[str] = ..., deployment_model: _Optional[_Union[_types_pb2.DeploymentModel, str]] = ..., tags: _Optional[_Mapping[str, str]] = ...) -> None: ...

class CreateApplicationResponse(_message.Message):
    __slots__ = ("application",)
    APPLICATION_FIELD_NUMBER: _ClassVar[int]
    application: _types_pb2.Application
    def __init__(self, application: _Optional[_Union[_types_pb2.Application, _Mapping]] = ...) -> None: ...

class UpdateApplicationRequest(_message.Message):
    __slots__ = ("id", "name", "description", "deployment_model", "tags")
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
    TAGS_FIELD_NUMBER: _ClassVar[int]
    id: int
    name: str
    description: str
    deployment_model: _types_pb2.DeploymentModel
    tags: _containers.ScalarMap[str, str]
    def __init__(self, id: _Optional[int] = ..., name: _Optional[str] = ..., description: _Optional[str] = ..., deployment_model: _Optional[_Union[_types_pb2.DeploymentModel, str]] = ..., tags: _Optional[_Mapping[str, str]] = ...) -> None: ...

class UpdateApplicationResponse(_message.Message):
    __slots__ = ("application",)
    APPLICATION_FIELD_NUMBER: _ClassVar[int]
    application: _types_pb2.Application
    def __init__(self, application: _Optional[_Union[_types_pb2.Application, _Mapping]] = ...) -> None: ...

class DeleteApplicationRequest(_message.Message):
    __slots__ = ("id",)
    ID_FIELD_NUMBER: _ClassVar[int]
    id: int
    def __init__(self, id: _Optional[int] = ...) -> None: ...

class DeleteApplicationResponse(_message.Message):
    __slots__ = ("success",)
    SUCCESS_FIELD_NUMBER: _ClassVar[int]
    success: bool
    def __init__(self, success: bool = ...) -> None: ...

class SyncWithElderRequest(_message.Message):
    __slots__ = ("application_id",)
    APPLICATION_ID_FIELD_NUMBER: _ClassVar[int]
    application_id: int
    def __init__(self, application_id: _Optional[int] = ...) -> None: ...

class SyncWithElderResponse(_message.Message):
    __slots__ = ("success", "elder_entity_id", "elder_service_id", "message")
    SUCCESS_FIELD_NUMBER: _ClassVar[int]
    ELDER_ENTITY_ID_FIELD_NUMBER: _ClassVar[int]
    ELDER_SERVICE_ID_FIELD_NUMBER: _ClassVar[int]
    MESSAGE_FIELD_NUMBER: _ClassVar[int]
    success: bool
    elder_entity_id: str
    elder_service_id: str
    message: str
    def __init__(self, success: bool = ..., elder_entity_id: _Optional[str] = ..., elder_service_id: _Optional[str] = ..., message: _Optional[str] = ...) -> None: ...

class ListCredentialsRequest(_message.Message):
    __slots__ = ("page", "page_size", "resource_id", "application_id")
    PAGE_FIELD_NUMBER: _ClassVar[int]
    PAGE_SIZE_FIELD_NUMBER: _ClassVar[int]
    RESOURCE_ID_FIELD_NUMBER: _ClassVar[int]
    APPLICATION_ID_FIELD_NUMBER: _ClassVar[int]
    page: int
    page_size: int
    resource_id: int
    application_id: int
    def __init__(self, page: _Optional[int] = ..., page_size: _Optional[int] = ..., resource_id: _Optional[int] = ..., application_id: _Optional[int] = ...) -> None: ...

class ListCredentialsResponse(_message.Message):
    __slots__ = ("credentials", "pagination")
    CREDENTIALS_FIELD_NUMBER: _ClassVar[int]
    PAGINATION_FIELD_NUMBER: _ClassVar[int]
    credentials: _containers.RepeatedCompositeFieldContainer[_types_pb2.Credential]
    pagination: _types_pb2.Pagination
    def __init__(self, credentials: _Optional[_Iterable[_Union[_types_pb2.Credential, _Mapping]]] = ..., pagination: _Optional[_Union[_types_pb2.Pagination, _Mapping]] = ...) -> None: ...

class GetCredentialRequest(_message.Message):
    __slots__ = ("id",)
    ID_FIELD_NUMBER: _ClassVar[int]
    id: int
    def __init__(self, id: _Optional[int] = ...) -> None: ...

class GetCredentialResponse(_message.Message):
    __slots__ = ("credential",)
    CREDENTIAL_FIELD_NUMBER: _ClassVar[int]
    credential: _types_pb2.Credential
    def __init__(self, credential: _Optional[_Union[_types_pb2.Credential, _Mapping]] = ...) -> None: ...

class CreateCredentialRequest(_message.Message):
    __slots__ = ("resource_id", "application_id", "credential_type", "username", "permissions", "expires_at", "auto_rotate", "rotation_interval_days", "iam_policy", "jwt_subject", "jwt_claims")
    class JwtClaimsEntry(_message.Message):
        __slots__ = ("key", "value")
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: str
        value: str
        def __init__(self, key: _Optional[str] = ..., value: _Optional[str] = ...) -> None: ...
    RESOURCE_ID_FIELD_NUMBER: _ClassVar[int]
    APPLICATION_ID_FIELD_NUMBER: _ClassVar[int]
    CREDENTIAL_TYPE_FIELD_NUMBER: _ClassVar[int]
    USERNAME_FIELD_NUMBER: _ClassVar[int]
    PERMISSIONS_FIELD_NUMBER: _ClassVar[int]
    EXPIRES_AT_FIELD_NUMBER: _ClassVar[int]
    AUTO_ROTATE_FIELD_NUMBER: _ClassVar[int]
    ROTATION_INTERVAL_DAYS_FIELD_NUMBER: _ClassVar[int]
    IAM_POLICY_FIELD_NUMBER: _ClassVar[int]
    JWT_SUBJECT_FIELD_NUMBER: _ClassVar[int]
    JWT_CLAIMS_FIELD_NUMBER: _ClassVar[int]
    resource_id: int
    application_id: int
    credential_type: _types_pb2.CredentialType
    username: str
    permissions: _containers.RepeatedScalarFieldContainer[str]
    expires_at: _timestamp_pb2.Timestamp
    auto_rotate: bool
    rotation_interval_days: int
    iam_policy: str
    jwt_subject: str
    jwt_claims: _containers.ScalarMap[str, str]
    def __init__(self, resource_id: _Optional[int] = ..., application_id: _Optional[int] = ..., credential_type: _Optional[_Union[_types_pb2.CredentialType, str]] = ..., username: _Optional[str] = ..., permissions: _Optional[_Iterable[str]] = ..., expires_at: _Optional[_Union[_timestamp_pb2.Timestamp, _Mapping]] = ..., auto_rotate: bool = ..., rotation_interval_days: _Optional[int] = ..., iam_policy: _Optional[str] = ..., jwt_subject: _Optional[str] = ..., jwt_claims: _Optional[_Mapping[str, str]] = ...) -> None: ...

class CreateCredentialResponse(_message.Message):
    __slots__ = ("credential", "password", "jwt_token", "mtls_certificate", "mtls_private_key")
    CREDENTIAL_FIELD_NUMBER: _ClassVar[int]
    PASSWORD_FIELD_NUMBER: _ClassVar[int]
    JWT_TOKEN_FIELD_NUMBER: _ClassVar[int]
    MTLS_CERTIFICATE_FIELD_NUMBER: _ClassVar[int]
    MTLS_PRIVATE_KEY_FIELD_NUMBER: _ClassVar[int]
    credential: _types_pb2.Credential
    password: str
    jwt_token: str
    mtls_certificate: str
    mtls_private_key: str
    def __init__(self, credential: _Optional[_Union[_types_pb2.Credential, _Mapping]] = ..., password: _Optional[str] = ..., jwt_token: _Optional[str] = ..., mtls_certificate: _Optional[str] = ..., mtls_private_key: _Optional[str] = ...) -> None: ...

class RotateCredentialRequest(_message.Message):
    __slots__ = ("id",)
    ID_FIELD_NUMBER: _ClassVar[int]
    id: int
    def __init__(self, id: _Optional[int] = ...) -> None: ...

class RotateCredentialResponse(_message.Message):
    __slots__ = ("credential", "new_password", "new_jwt_token", "new_mtls_certificate", "new_mtls_private_key")
    CREDENTIAL_FIELD_NUMBER: _ClassVar[int]
    NEW_PASSWORD_FIELD_NUMBER: _ClassVar[int]
    NEW_JWT_TOKEN_FIELD_NUMBER: _ClassVar[int]
    NEW_MTLS_CERTIFICATE_FIELD_NUMBER: _ClassVar[int]
    NEW_MTLS_PRIVATE_KEY_FIELD_NUMBER: _ClassVar[int]
    credential: _types_pb2.Credential
    new_password: str
    new_jwt_token: str
    new_mtls_certificate: str
    new_mtls_private_key: str
    def __init__(self, credential: _Optional[_Union[_types_pb2.Credential, _Mapping]] = ..., new_password: _Optional[str] = ..., new_jwt_token: _Optional[str] = ..., new_mtls_certificate: _Optional[str] = ..., new_mtls_private_key: _Optional[str] = ...) -> None: ...

class ConfigureAutoRotationRequest(_message.Message):
    __slots__ = ("id", "auto_rotate", "rotation_interval_days")
    ID_FIELD_NUMBER: _ClassVar[int]
    AUTO_ROTATE_FIELD_NUMBER: _ClassVar[int]
    ROTATION_INTERVAL_DAYS_FIELD_NUMBER: _ClassVar[int]
    id: int
    auto_rotate: bool
    rotation_interval_days: int
    def __init__(self, id: _Optional[int] = ..., auto_rotate: bool = ..., rotation_interval_days: _Optional[int] = ...) -> None: ...

class ConfigureAutoRotationResponse(_message.Message):
    __slots__ = ("credential",)
    CREDENTIAL_FIELD_NUMBER: _ClassVar[int]
    credential: _types_pb2.Credential
    def __init__(self, credential: _Optional[_Union[_types_pb2.Credential, _Mapping]] = ...) -> None: ...

class DeleteCredentialRequest(_message.Message):
    __slots__ = ("id",)
    ID_FIELD_NUMBER: _ClassVar[int]
    id: int
    def __init__(self, id: _Optional[int] = ...) -> None: ...

class DeleteCredentialResponse(_message.Message):
    __slots__ = ("success",)
    SUCCESS_FIELD_NUMBER: _ClassVar[int]
    success: bool
    def __init__(self, success: bool = ...) -> None: ...

class ListProvidersRequest(_message.Message):
    __slots__ = ("page", "page_size", "provider_type")
    PAGE_FIELD_NUMBER: _ClassVar[int]
    PAGE_SIZE_FIELD_NUMBER: _ClassVar[int]
    PROVIDER_TYPE_FIELD_NUMBER: _ClassVar[int]
    page: int
    page_size: int
    provider_type: _types_pb2.ProviderType
    def __init__(self, page: _Optional[int] = ..., page_size: _Optional[int] = ..., provider_type: _Optional[_Union[_types_pb2.ProviderType, str]] = ...) -> None: ...

class ListProvidersResponse(_message.Message):
    __slots__ = ("providers", "pagination")
    PROVIDERS_FIELD_NUMBER: _ClassVar[int]
    PAGINATION_FIELD_NUMBER: _ClassVar[int]
    providers: _containers.RepeatedCompositeFieldContainer[_types_pb2.Provider]
    pagination: _types_pb2.Pagination
    def __init__(self, providers: _Optional[_Iterable[_Union[_types_pb2.Provider, _Mapping]]] = ..., pagination: _Optional[_Union[_types_pb2.Pagination, _Mapping]] = ...) -> None: ...

class GetProviderRequest(_message.Message):
    __slots__ = ("id",)
    ID_FIELD_NUMBER: _ClassVar[int]
    id: int
    def __init__(self, id: _Optional[int] = ...) -> None: ...

class GetProviderResponse(_message.Message):
    __slots__ = ("provider",)
    PROVIDER_FIELD_NUMBER: _ClassVar[int]
    provider: _types_pb2.Provider
    def __init__(self, provider: _Optional[_Union[_types_pb2.Provider, _Mapping]] = ...) -> None: ...

class CreateProviderRequest(_message.Message):
    __slots__ = ("name", "provider_type", "configuration", "credentials_secret_name")
    NAME_FIELD_NUMBER: _ClassVar[int]
    PROVIDER_TYPE_FIELD_NUMBER: _ClassVar[int]
    CONFIGURATION_FIELD_NUMBER: _ClassVar[int]
    CREDENTIALS_SECRET_NAME_FIELD_NUMBER: _ClassVar[int]
    name: str
    provider_type: _types_pb2.ProviderType
    configuration: str
    credentials_secret_name: str
    def __init__(self, name: _Optional[str] = ..., provider_type: _Optional[_Union[_types_pb2.ProviderType, str]] = ..., configuration: _Optional[str] = ..., credentials_secret_name: _Optional[str] = ...) -> None: ...

class CreateProviderResponse(_message.Message):
    __slots__ = ("provider",)
    PROVIDER_FIELD_NUMBER: _ClassVar[int]
    provider: _types_pb2.Provider
    def __init__(self, provider: _Optional[_Union[_types_pb2.Provider, _Mapping]] = ...) -> None: ...

class UpdateProviderRequest(_message.Message):
    __slots__ = ("id", "name", "configuration", "credentials_secret_name", "enabled")
    ID_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    CONFIGURATION_FIELD_NUMBER: _ClassVar[int]
    CREDENTIALS_SECRET_NAME_FIELD_NUMBER: _ClassVar[int]
    ENABLED_FIELD_NUMBER: _ClassVar[int]
    id: int
    name: str
    configuration: str
    credentials_secret_name: str
    enabled: bool
    def __init__(self, id: _Optional[int] = ..., name: _Optional[str] = ..., configuration: _Optional[str] = ..., credentials_secret_name: _Optional[str] = ..., enabled: bool = ...) -> None: ...

class UpdateProviderResponse(_message.Message):
    __slots__ = ("provider",)
    PROVIDER_FIELD_NUMBER: _ClassVar[int]
    provider: _types_pb2.Provider
    def __init__(self, provider: _Optional[_Union[_types_pb2.Provider, _Mapping]] = ...) -> None: ...

class DeleteProviderRequest(_message.Message):
    __slots__ = ("id",)
    ID_FIELD_NUMBER: _ClassVar[int]
    id: int
    def __init__(self, id: _Optional[int] = ...) -> None: ...

class DeleteProviderResponse(_message.Message):
    __slots__ = ("success",)
    SUCCESS_FIELD_NUMBER: _ClassVar[int]
    success: bool
    def __init__(self, success: bool = ...) -> None: ...

class TestProviderRequest(_message.Message):
    __slots__ = ("id",)
    ID_FIELD_NUMBER: _ClassVar[int]
    id: int
    def __init__(self, id: _Optional[int] = ...) -> None: ...

class TestProviderResponse(_message.Message):
    __slots__ = ("success", "message")
    SUCCESS_FIELD_NUMBER: _ClassVar[int]
    MESSAGE_FIELD_NUMBER: _ClassVar[int]
    success: bool
    message: str
    def __init__(self, success: bool = ..., message: _Optional[str] = ...) -> None: ...

class ConfigureMarchProxyRequest(_message.Message):
    __slots__ = ("resource_id", "max_connections", "query_rate_limit", "enable_sql_injection_detection")
    RESOURCE_ID_FIELD_NUMBER: _ClassVar[int]
    MAX_CONNECTIONS_FIELD_NUMBER: _ClassVar[int]
    QUERY_RATE_LIMIT_FIELD_NUMBER: _ClassVar[int]
    ENABLE_SQL_INJECTION_DETECTION_FIELD_NUMBER: _ClassVar[int]
    resource_id: int
    max_connections: int
    query_rate_limit: int
    enable_sql_injection_detection: bool
    def __init__(self, resource_id: _Optional[int] = ..., max_connections: _Optional[int] = ..., query_rate_limit: _Optional[int] = ..., enable_sql_injection_detection: bool = ...) -> None: ...

class ConfigureMarchProxyResponse(_message.Message):
    __slots__ = ("success", "proxy_endpoint", "proxy_port", "message")
    SUCCESS_FIELD_NUMBER: _ClassVar[int]
    PROXY_ENDPOINT_FIELD_NUMBER: _ClassVar[int]
    PROXY_PORT_FIELD_NUMBER: _ClassVar[int]
    MESSAGE_FIELD_NUMBER: _ClassVar[int]
    success: bool
    proxy_endpoint: str
    proxy_port: int
    message: str
    def __init__(self, success: bool = ..., proxy_endpoint: _Optional[str] = ..., proxy_port: _Optional[int] = ..., message: _Optional[str] = ...) -> None: ...

class RemoveMarchProxyRequest(_message.Message):
    __slots__ = ("resource_id",)
    RESOURCE_ID_FIELD_NUMBER: _ClassVar[int]
    resource_id: int
    def __init__(self, resource_id: _Optional[int] = ...) -> None: ...

class RemoveMarchProxyResponse(_message.Message):
    __slots__ = ("success",)
    SUCCESS_FIELD_NUMBER: _ClassVar[int]
    success: bool
    def __init__(self, success: bool = ...) -> None: ...

class SyncMarchProxyRequest(_message.Message):
    __slots__ = ("resource_id",)
    RESOURCE_ID_FIELD_NUMBER: _ClassVar[int]
    resource_id: int
    def __init__(self, resource_id: _Optional[int] = ...) -> None: ...

class SyncMarchProxyResponse(_message.Message):
    __slots__ = ("success", "health_status", "metrics")
    class MetricsEntry(_message.Message):
        __slots__ = ("key", "value")
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: str
        value: float
        def __init__(self, key: _Optional[str] = ..., value: _Optional[float] = ...) -> None: ...
    SUCCESS_FIELD_NUMBER: _ClassVar[int]
    HEALTH_STATUS_FIELD_NUMBER: _ClassVar[int]
    METRICS_FIELD_NUMBER: _ClassVar[int]
    success: bool
    health_status: str
    metrics: _containers.ScalarMap[str, float]
    def __init__(self, success: bool = ..., health_status: _Optional[str] = ..., metrics: _Optional[_Mapping[str, float]] = ...) -> None: ...

class AddTagsRequest(_message.Message):
    __slots__ = ("resource_id", "tags")
    class TagsEntry(_message.Message):
        __slots__ = ("key", "value")
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: str
        value: str
        def __init__(self, key: _Optional[str] = ..., value: _Optional[str] = ...) -> None: ...
    RESOURCE_ID_FIELD_NUMBER: _ClassVar[int]
    TAGS_FIELD_NUMBER: _ClassVar[int]
    resource_id: int
    tags: _containers.ScalarMap[str, str]
    def __init__(self, resource_id: _Optional[int] = ..., tags: _Optional[_Mapping[str, str]] = ...) -> None: ...

class AddTagsResponse(_message.Message):
    __slots__ = ("resource",)
    RESOURCE_FIELD_NUMBER: _ClassVar[int]
    resource: _types_pb2.Resource
    def __init__(self, resource: _Optional[_Union[_types_pb2.Resource, _Mapping]] = ...) -> None: ...

class RemoveTagRequest(_message.Message):
    __slots__ = ("resource_id", "tag_key")
    RESOURCE_ID_FIELD_NUMBER: _ClassVar[int]
    TAG_KEY_FIELD_NUMBER: _ClassVar[int]
    resource_id: int
    tag_key: str
    def __init__(self, resource_id: _Optional[int] = ..., tag_key: _Optional[str] = ...) -> None: ...

class RemoveTagResponse(_message.Message):
    __slots__ = ("resource",)
    RESOURCE_FIELD_NUMBER: _ClassVar[int]
    resource: _types_pb2.Resource
    def __init__(self, resource: _Optional[_Union[_types_pb2.Resource, _Mapping]] = ...) -> None: ...

class SyncTagsRequest(_message.Message):
    __slots__ = ("resource_id",)
    RESOURCE_ID_FIELD_NUMBER: _ClassVar[int]
    resource_id: int
    def __init__(self, resource_id: _Optional[int] = ...) -> None: ...

class SyncTagsResponse(_message.Message):
    __slots__ = ("success", "message")
    SUCCESS_FIELD_NUMBER: _ClassVar[int]
    MESSAGE_FIELD_NUMBER: _ClassVar[int]
    success: bool
    message: str
    def __init__(self, success: bool = ..., message: _Optional[str] = ...) -> None: ...
