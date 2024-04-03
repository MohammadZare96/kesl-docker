

class CommonErrorResponse:

    ERR_NOT_SUPPORTED_CONTENT_TYPE = (400, 'NOT_SUPPORTED_CONTENT_TYPE', 'Not supported Content-Type')
    ERR_INVALID_JSON               = (400, 'INVALID_JSON', 'Invalid JSON data')
    ERR_INVALID_LINK               = (400, 'INVALID_LINK', 'Invalid image url')
    ERR_NOTHING_TO_PROCESS         = (400, 'NOTHING_TO_PROCESS', 'Nothing to process')
    ERR_FORBIDDEN                  = (403, 'FORBIDDEN', 'Forbidden')
    ERR_OBJECT_NOT_FOUND           = (404, 'OBJECT NOT FOUND', 'Object not found')
    ERR_INTERNAL_SERVER_ERROR      = (500, 'INTERNAL_SERVER_ERROR', 'Internal server error')
    ERR_INVALID_URL_FORMAT         = (400, 'INVALID_URL_FORMAT', 'Invalid url format')
    ERR_NOT_IMPLEMENTED            = (501, 'NOT IMPLEMENTED', 'Not supported object type')
    ERR_SERVICE_NOT_AVAILABLE      = (503, 'SERVICE NOT AVAILABLE', 'Service not available')

    @staticmethod
    def make_error(error_info, details=None):
        response = {
            'status': 'error',
            'error': {
                'code': error_info[1],
                'message': error_info[2]
            }
        }
        if details:
            response['error']['details'] = details
        return response, error_info[0]
