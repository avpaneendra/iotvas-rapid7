"""
    IoTVAS API

    IOTVAS API enables you to discover IoT/Connected devices in the network and provides      detailed real-time risk analysis, including firmware vulnerability analysis without requiring the user to upload the firmware file.     Please visit the [signup page](https://iotvas-api.firmalyzer.com/portal/signup) to create an API key.     IoTVAS API can be easily integrated with vulnerability scanning and network port scanner tools. For example,     we have also released the [IOTVAS NSE script](https://github.com/firmalyzer/iotvas-nmap) that turns the nmap port scanner      to a IoT/connected device discovery and real-time risk assessment tool. For more infromation on IoTVAS and other      solutions please visit [Firmalyzer web site](https://www.firmalyzer.com).  # noqa: E501

    The version of the OpenAPI document: 1.0
    Generated by: https://openapi-generator.tech
"""


import re  # noqa: F401
import sys  # noqa: F401

from iotvas.api_client import ApiClient, Endpoint as _Endpoint
from iotvas.model_utils import (  # noqa: F401
    check_allowed_values,
    check_validations,
    date,
    datetime,
    file_type,
    none_type,
    validate_and_convert_types
)
from iotvas.model.config_issue import ConfigIssue
from iotvas.model.crypto_key import CryptoKey
from iotvas.model.default_account import DefaultAccount
from iotvas.model.expired_cert import ExpiredCert
from iotvas.model.firmware_risk import FirmwareRisk
from iotvas.model.http_validation_error import HTTPValidationError
from iotvas.model.weak_cert import WeakCert


class FirmwareApi(object):
    """NOTE: This class is auto generated by OpenAPI Generator
    Ref: https://openapi-generator.tech

    Do not edit the class manually.
    """

    def __init__(self, api_client=None):
        if api_client is None:
            api_client = ApiClient()
        self.api_client = api_client

        def __get_accounts(
            self,
            firmware_hash,
            **kwargs
        ):
            """Get default accounts and password hashes of a firmware  # noqa: E501

            This method makes a synchronous HTTP request by default. To make an
            asynchronous HTTP request, please pass async_req=True

            >>> thread = api.get_accounts(firmware_hash, async_req=True)
            >>> result = thread.get()

            Args:
                firmware_hash (str): SHA2 hash of device firmware

            Keyword Args:
                _return_http_data_only (bool): response data without head status
                    code and headers. Default is True.
                _preload_content (bool): if False, the urllib3.HTTPResponse object
                    will be returned without reading/decoding response data.
                    Default is True.
                _request_timeout (int/float/tuple): timeout setting for this request. If
                    one number provided, it will be total request timeout. It can also
                    be a pair (tuple) of (connection, read) timeouts.
                    Default is None.
                _check_input_type (bool): specifies if type checking
                    should be done one the data sent to the server.
                    Default is True.
                _check_return_type (bool): specifies if type checking
                    should be done one the data received from the server.
                    Default is True.
                _host_index (int/None): specifies the index of the server
                    that we want to use.
                    Default is read from the configuration.
                async_req (bool): execute request asynchronously

            Returns:
                [DefaultAccount]
                    If the method is called asynchronously, returns the request
                    thread.
            """
            kwargs['async_req'] = kwargs.get(
                'async_req', False
            )
            kwargs['_return_http_data_only'] = kwargs.get(
                '_return_http_data_only', True
            )
            kwargs['_preload_content'] = kwargs.get(
                '_preload_content', True
            )
            kwargs['_request_timeout'] = kwargs.get(
                '_request_timeout', None
            )
            kwargs['_check_input_type'] = kwargs.get(
                '_check_input_type', True
            )
            kwargs['_check_return_type'] = kwargs.get(
                '_check_return_type', True
            )
            kwargs['_host_index'] = kwargs.get('_host_index')
            kwargs['firmware_hash'] = \
                firmware_hash
            return self.call_with_http_info(**kwargs)

        self.get_accounts = _Endpoint(
            settings={
                'response_type': ([DefaultAccount],),
                'auth': [
                    'api-key-header'
                ],
                'endpoint_path': '/firmware/{firmware_hash}/accounts',
                'operation_id': 'get_accounts',
                'http_method': 'GET',
                'servers': None,
            },
            params_map={
                'all': [
                    'firmware_hash',
                ],
                'required': [
                    'firmware_hash',
                ],
                'nullable': [
                ],
                'enum': [
                ],
                'validation': [
                ]
            },
            root_map={
                'validations': {
                },
                'allowed_values': {
                },
                'openapi_types': {
                    'firmware_hash':
                        (str,),
                },
                'attribute_map': {
                    'firmware_hash': 'firmware_hash',
                },
                'location_map': {
                    'firmware_hash': 'path',
                },
                'collection_format_map': {
                }
            },
            headers_map={
                'accept': [
                    'application/json'
                ],
                'content_type': [],
            },
            api_client=api_client,
            callable=__get_accounts
        )

        def __get_config_issues(
            self,
            firmware_hash,
            **kwargs
        ):
            """Get default OS configuration issues of a device firmware  # noqa: E501

            This method makes a synchronous HTTP request by default. To make an
            asynchronous HTTP request, please pass async_req=True

            >>> thread = api.get_config_issues(firmware_hash, async_req=True)
            >>> result = thread.get()

            Args:
                firmware_hash (str): SHA2 hash of device firmware

            Keyword Args:
                _return_http_data_only (bool): response data without head status
                    code and headers. Default is True.
                _preload_content (bool): if False, the urllib3.HTTPResponse object
                    will be returned without reading/decoding response data.
                    Default is True.
                _request_timeout (int/float/tuple): timeout setting for this request. If
                    one number provided, it will be total request timeout. It can also
                    be a pair (tuple) of (connection, read) timeouts.
                    Default is None.
                _check_input_type (bool): specifies if type checking
                    should be done one the data sent to the server.
                    Default is True.
                _check_return_type (bool): specifies if type checking
                    should be done one the data received from the server.
                    Default is True.
                _host_index (int/None): specifies the index of the server
                    that we want to use.
                    Default is read from the configuration.
                async_req (bool): execute request asynchronously

            Returns:
                [ConfigIssue]
                    If the method is called asynchronously, returns the request
                    thread.
            """
            kwargs['async_req'] = kwargs.get(
                'async_req', False
            )
            kwargs['_return_http_data_only'] = kwargs.get(
                '_return_http_data_only', True
            )
            kwargs['_preload_content'] = kwargs.get(
                '_preload_content', True
            )
            kwargs['_request_timeout'] = kwargs.get(
                '_request_timeout', None
            )
            kwargs['_check_input_type'] = kwargs.get(
                '_check_input_type', True
            )
            kwargs['_check_return_type'] = kwargs.get(
                '_check_return_type', True
            )
            kwargs['_host_index'] = kwargs.get('_host_index')
            kwargs['firmware_hash'] = \
                firmware_hash
            return self.call_with_http_info(**kwargs)

        self.get_config_issues = _Endpoint(
            settings={
                'response_type': ([ConfigIssue],),
                'auth': [
                    'api-key-header'
                ],
                'endpoint_path': '/firmware/{firmware_hash}/config-issues',
                'operation_id': 'get_config_issues',
                'http_method': 'GET',
                'servers': None,
            },
            params_map={
                'all': [
                    'firmware_hash',
                ],
                'required': [
                    'firmware_hash',
                ],
                'nullable': [
                ],
                'enum': [
                ],
                'validation': [
                ]
            },
            root_map={
                'validations': {
                },
                'allowed_values': {
                },
                'openapi_types': {
                    'firmware_hash':
                        (str,),
                },
                'attribute_map': {
                    'firmware_hash': 'firmware_hash',
                },
                'location_map': {
                    'firmware_hash': 'path',
                },
                'collection_format_map': {
                }
            },
            headers_map={
                'accept': [
                    'application/json'
                ],
                'content_type': [],
            },
            api_client=api_client,
            callable=__get_config_issues
        )

        def __get_expired_certs(
            self,
            firmware_hash,
            **kwargs
        ):
            """Get expired digital certificates embedded in a device firmware  # noqa: E501

            This method makes a synchronous HTTP request by default. To make an
            asynchronous HTTP request, please pass async_req=True

            >>> thread = api.get_expired_certs(firmware_hash, async_req=True)
            >>> result = thread.get()

            Args:
                firmware_hash (str): SHA2 hash of device firmware

            Keyword Args:
                _return_http_data_only (bool): response data without head status
                    code and headers. Default is True.
                _preload_content (bool): if False, the urllib3.HTTPResponse object
                    will be returned without reading/decoding response data.
                    Default is True.
                _request_timeout (int/float/tuple): timeout setting for this request. If
                    one number provided, it will be total request timeout. It can also
                    be a pair (tuple) of (connection, read) timeouts.
                    Default is None.
                _check_input_type (bool): specifies if type checking
                    should be done one the data sent to the server.
                    Default is True.
                _check_return_type (bool): specifies if type checking
                    should be done one the data received from the server.
                    Default is True.
                _host_index (int/None): specifies the index of the server
                    that we want to use.
                    Default is read from the configuration.
                async_req (bool): execute request asynchronously

            Returns:
                [ExpiredCert]
                    If the method is called asynchronously, returns the request
                    thread.
            """
            kwargs['async_req'] = kwargs.get(
                'async_req', False
            )
            kwargs['_return_http_data_only'] = kwargs.get(
                '_return_http_data_only', True
            )
            kwargs['_preload_content'] = kwargs.get(
                '_preload_content', True
            )
            kwargs['_request_timeout'] = kwargs.get(
                '_request_timeout', None
            )
            kwargs['_check_input_type'] = kwargs.get(
                '_check_input_type', True
            )
            kwargs['_check_return_type'] = kwargs.get(
                '_check_return_type', True
            )
            kwargs['_host_index'] = kwargs.get('_host_index')
            kwargs['firmware_hash'] = \
                firmware_hash
            return self.call_with_http_info(**kwargs)

        self.get_expired_certs = _Endpoint(
            settings={
                'response_type': ([ExpiredCert],),
                'auth': [
                    'api-key-header'
                ],
                'endpoint_path': '/firmware/{firmware_hash}/expired-certs',
                'operation_id': 'get_expired_certs',
                'http_method': 'GET',
                'servers': None,
            },
            params_map={
                'all': [
                    'firmware_hash',
                ],
                'required': [
                    'firmware_hash',
                ],
                'nullable': [
                ],
                'enum': [
                ],
                'validation': [
                ]
            },
            root_map={
                'validations': {
                },
                'allowed_values': {
                },
                'openapi_types': {
                    'firmware_hash':
                        (str,),
                },
                'attribute_map': {
                    'firmware_hash': 'firmware_hash',
                },
                'location_map': {
                    'firmware_hash': 'path',
                },
                'collection_format_map': {
                }
            },
            headers_map={
                'accept': [
                    'application/json'
                ],
                'content_type': [],
            },
            api_client=api_client,
            callable=__get_expired_certs
        )

        def __get_private_keys(
            self,
            firmware_hash,
            **kwargs
        ):
            """Get private crypto keys embedded in a device firmware  # noqa: E501

            This method makes a synchronous HTTP request by default. To make an
            asynchronous HTTP request, please pass async_req=True

            >>> thread = api.get_private_keys(firmware_hash, async_req=True)
            >>> result = thread.get()

            Args:
                firmware_hash (str): SHA2 hash of device firmware

            Keyword Args:
                _return_http_data_only (bool): response data without head status
                    code and headers. Default is True.
                _preload_content (bool): if False, the urllib3.HTTPResponse object
                    will be returned without reading/decoding response data.
                    Default is True.
                _request_timeout (int/float/tuple): timeout setting for this request. If
                    one number provided, it will be total request timeout. It can also
                    be a pair (tuple) of (connection, read) timeouts.
                    Default is None.
                _check_input_type (bool): specifies if type checking
                    should be done one the data sent to the server.
                    Default is True.
                _check_return_type (bool): specifies if type checking
                    should be done one the data received from the server.
                    Default is True.
                _host_index (int/None): specifies the index of the server
                    that we want to use.
                    Default is read from the configuration.
                async_req (bool): execute request asynchronously

            Returns:
                [CryptoKey]
                    If the method is called asynchronously, returns the request
                    thread.
            """
            kwargs['async_req'] = kwargs.get(
                'async_req', False
            )
            kwargs['_return_http_data_only'] = kwargs.get(
                '_return_http_data_only', True
            )
            kwargs['_preload_content'] = kwargs.get(
                '_preload_content', True
            )
            kwargs['_request_timeout'] = kwargs.get(
                '_request_timeout', None
            )
            kwargs['_check_input_type'] = kwargs.get(
                '_check_input_type', True
            )
            kwargs['_check_return_type'] = kwargs.get(
                '_check_return_type', True
            )
            kwargs['_host_index'] = kwargs.get('_host_index')
            kwargs['firmware_hash'] = \
                firmware_hash
            return self.call_with_http_info(**kwargs)

        self.get_private_keys = _Endpoint(
            settings={
                'response_type': ([CryptoKey],),
                'auth': [
                    'api-key-header'
                ],
                'endpoint_path': '/firmware/{firmware_hash}/private-keys',
                'operation_id': 'get_private_keys',
                'http_method': 'GET',
                'servers': None,
            },
            params_map={
                'all': [
                    'firmware_hash',
                ],
                'required': [
                    'firmware_hash',
                ],
                'nullable': [
                ],
                'enum': [
                ],
                'validation': [
                ]
            },
            root_map={
                'validations': {
                },
                'allowed_values': {
                },
                'openapi_types': {
                    'firmware_hash':
                        (str,),
                },
                'attribute_map': {
                    'firmware_hash': 'firmware_hash',
                },
                'location_map': {
                    'firmware_hash': 'path',
                },
                'collection_format_map': {
                }
            },
            headers_map={
                'accept': [
                    'application/json'
                ],
                'content_type': [],
            },
            api_client=api_client,
            callable=__get_private_keys
        )

        def __get_risk(
            self,
            firmware_hash,
            **kwargs
        ):
            """Get iot device firmware risk analysis  # noqa: E501

            This method makes a synchronous HTTP request by default. To make an
            asynchronous HTTP request, please pass async_req=True

            >>> thread = api.get_risk(firmware_hash, async_req=True)
            >>> result = thread.get()

            Args:
                firmware_hash (str): SHA2 hash of device firmware

            Keyword Args:
                _return_http_data_only (bool): response data without head status
                    code and headers. Default is True.
                _preload_content (bool): if False, the urllib3.HTTPResponse object
                    will be returned without reading/decoding response data.
                    Default is True.
                _request_timeout (int/float/tuple): timeout setting for this request. If
                    one number provided, it will be total request timeout. It can also
                    be a pair (tuple) of (connection, read) timeouts.
                    Default is None.
                _check_input_type (bool): specifies if type checking
                    should be done one the data sent to the server.
                    Default is True.
                _check_return_type (bool): specifies if type checking
                    should be done one the data received from the server.
                    Default is True.
                _host_index (int/None): specifies the index of the server
                    that we want to use.
                    Default is read from the configuration.
                async_req (bool): execute request asynchronously

            Returns:
                FirmwareRisk
                    If the method is called asynchronously, returns the request
                    thread.
            """
            kwargs['async_req'] = kwargs.get(
                'async_req', False
            )
            kwargs['_return_http_data_only'] = kwargs.get(
                '_return_http_data_only', True
            )
            kwargs['_preload_content'] = kwargs.get(
                '_preload_content', True
            )
            kwargs['_request_timeout'] = kwargs.get(
                '_request_timeout', None
            )
            kwargs['_check_input_type'] = kwargs.get(
                '_check_input_type', True
            )
            kwargs['_check_return_type'] = kwargs.get(
                '_check_return_type', True
            )
            kwargs['_host_index'] = kwargs.get('_host_index')
            kwargs['firmware_hash'] = \
                firmware_hash
            return self.call_with_http_info(**kwargs)

        self.get_risk = _Endpoint(
            settings={
                'response_type': (FirmwareRisk,),
                'auth': [
                    'api-key-header'
                ],
                'endpoint_path': '/firmware/{firmware_hash}/risk',
                'operation_id': 'get_risk',
                'http_method': 'GET',
                'servers': None,
            },
            params_map={
                'all': [
                    'firmware_hash',
                ],
                'required': [
                    'firmware_hash',
                ],
                'nullable': [
                ],
                'enum': [
                ],
                'validation': [
                ]
            },
            root_map={
                'validations': {
                },
                'allowed_values': {
                },
                'openapi_types': {
                    'firmware_hash':
                        (str,),
                },
                'attribute_map': {
                    'firmware_hash': 'firmware_hash',
                },
                'location_map': {
                    'firmware_hash': 'path',
                },
                'collection_format_map': {
                }
            },
            headers_map={
                'accept': [
                    'application/json'
                ],
                'content_type': [],
            },
            api_client=api_client,
            callable=__get_risk
        )

        def __get_weak_certs(
            self,
            firmware_hash,
            **kwargs
        ):
            """Get certificates with weak fingerprinting algorithms that are mebedded in a device firmware  # noqa: E501

            This method makes a synchronous HTTP request by default. To make an
            asynchronous HTTP request, please pass async_req=True

            >>> thread = api.get_weak_certs(firmware_hash, async_req=True)
            >>> result = thread.get()

            Args:
                firmware_hash (str): SHA2 hash of device firmware

            Keyword Args:
                _return_http_data_only (bool): response data without head status
                    code and headers. Default is True.
                _preload_content (bool): if False, the urllib3.HTTPResponse object
                    will be returned without reading/decoding response data.
                    Default is True.
                _request_timeout (int/float/tuple): timeout setting for this request. If
                    one number provided, it will be total request timeout. It can also
                    be a pair (tuple) of (connection, read) timeouts.
                    Default is None.
                _check_input_type (bool): specifies if type checking
                    should be done one the data sent to the server.
                    Default is True.
                _check_return_type (bool): specifies if type checking
                    should be done one the data received from the server.
                    Default is True.
                _host_index (int/None): specifies the index of the server
                    that we want to use.
                    Default is read from the configuration.
                async_req (bool): execute request asynchronously

            Returns:
                [WeakCert]
                    If the method is called asynchronously, returns the request
                    thread.
            """
            kwargs['async_req'] = kwargs.get(
                'async_req', False
            )
            kwargs['_return_http_data_only'] = kwargs.get(
                '_return_http_data_only', True
            )
            kwargs['_preload_content'] = kwargs.get(
                '_preload_content', True
            )
            kwargs['_request_timeout'] = kwargs.get(
                '_request_timeout', None
            )
            kwargs['_check_input_type'] = kwargs.get(
                '_check_input_type', True
            )
            kwargs['_check_return_type'] = kwargs.get(
                '_check_return_type', True
            )
            kwargs['_host_index'] = kwargs.get('_host_index')
            kwargs['firmware_hash'] = \
                firmware_hash
            return self.call_with_http_info(**kwargs)

        self.get_weak_certs = _Endpoint(
            settings={
                'response_type': ([WeakCert],),
                'auth': [
                    'api-key-header'
                ],
                'endpoint_path': '/firmware/{firmware_hash}/weak-certs',
                'operation_id': 'get_weak_certs',
                'http_method': 'GET',
                'servers': None,
            },
            params_map={
                'all': [
                    'firmware_hash',
                ],
                'required': [
                    'firmware_hash',
                ],
                'nullable': [
                ],
                'enum': [
                ],
                'validation': [
                ]
            },
            root_map={
                'validations': {
                },
                'allowed_values': {
                },
                'openapi_types': {
                    'firmware_hash':
                        (str,),
                },
                'attribute_map': {
                    'firmware_hash': 'firmware_hash',
                },
                'location_map': {
                    'firmware_hash': 'path',
                },
                'collection_format_map': {
                }
            },
            headers_map={
                'accept': [
                    'application/json'
                ],
                'content_type': [],
            },
            api_client=api_client,
            callable=__get_weak_certs
        )

        def __get_weak_keys(
            self,
            firmware_hash,
            **kwargs
        ):
            """Get weak crypto keys with short length  # noqa: E501

            This method makes a synchronous HTTP request by default. To make an
            asynchronous HTTP request, please pass async_req=True

            >>> thread = api.get_weak_keys(firmware_hash, async_req=True)
            >>> result = thread.get()

            Args:
                firmware_hash (str): SHA2 hash of device firmware

            Keyword Args:
                _return_http_data_only (bool): response data without head status
                    code and headers. Default is True.
                _preload_content (bool): if False, the urllib3.HTTPResponse object
                    will be returned without reading/decoding response data.
                    Default is True.
                _request_timeout (int/float/tuple): timeout setting for this request. If
                    one number provided, it will be total request timeout. It can also
                    be a pair (tuple) of (connection, read) timeouts.
                    Default is None.
                _check_input_type (bool): specifies if type checking
                    should be done one the data sent to the server.
                    Default is True.
                _check_return_type (bool): specifies if type checking
                    should be done one the data received from the server.
                    Default is True.
                _host_index (int/None): specifies the index of the server
                    that we want to use.
                    Default is read from the configuration.
                async_req (bool): execute request asynchronously

            Returns:
                [CryptoKey]
                    If the method is called asynchronously, returns the request
                    thread.
            """
            kwargs['async_req'] = kwargs.get(
                'async_req', False
            )
            kwargs['_return_http_data_only'] = kwargs.get(
                '_return_http_data_only', True
            )
            kwargs['_preload_content'] = kwargs.get(
                '_preload_content', True
            )
            kwargs['_request_timeout'] = kwargs.get(
                '_request_timeout', None
            )
            kwargs['_check_input_type'] = kwargs.get(
                '_check_input_type', True
            )
            kwargs['_check_return_type'] = kwargs.get(
                '_check_return_type', True
            )
            kwargs['_host_index'] = kwargs.get('_host_index')
            kwargs['firmware_hash'] = \
                firmware_hash
            return self.call_with_http_info(**kwargs)

        self.get_weak_keys = _Endpoint(
            settings={
                'response_type': ([CryptoKey],),
                'auth': [
                    'api-key-header'
                ],
                'endpoint_path': '/firmware/{firmware_hash}/weak-keys',
                'operation_id': 'get_weak_keys',
                'http_method': 'GET',
                'servers': None,
            },
            params_map={
                'all': [
                    'firmware_hash',
                ],
                'required': [
                    'firmware_hash',
                ],
                'nullable': [
                ],
                'enum': [
                ],
                'validation': [
                ]
            },
            root_map={
                'validations': {
                },
                'allowed_values': {
                },
                'openapi_types': {
                    'firmware_hash':
                        (str,),
                },
                'attribute_map': {
                    'firmware_hash': 'firmware_hash',
                },
                'location_map': {
                    'firmware_hash': 'path',
                },
                'collection_format_map': {
                }
            },
            headers_map={
                'accept': [
                    'application/json'
                ],
                'content_type': [],
            },
            api_client=api_client,
            callable=__get_weak_keys
        )