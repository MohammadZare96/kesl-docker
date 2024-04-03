from pydantic import BaseModel, Field, validator
from control import Control
from service_types import SpecSingleton
from threading import Lock


class ProductInfoScheme(BaseModel):
    databases_loaded: bool = Field(False, alias="Application databases loaded")
    databases_date: str = Field("Not available", alias="Last release date of databases")
    policy: str = Field("Not available", alias="Policy")
    version: str = Field("Not available", alias="Version")
    license_info: str = Field("Not available", alias='License information')
    license_expiration: str = Field("Not available", alias="License expiration date")

    @validator('databases_loaded', pre=True)
    def convert_bool(cls, value):
        return False if value == 'None' else True

    class Config:
        validate_assignment = True
        allow_population_by_alias = True


class ProductInfo(Control, metaclass=SpecSingleton):

    def __init__(self):
        self.__mutex = Lock()
        self.__product_info = ProductInfoScheme()
        self.__product_avail_flag = False
        self.__product_restarting_flag = False
        super(ProductInfo, self).__init__('/usr/bin/kesl-control')

    @property
    def restart_flag(self):
        with self.__mutex:
            return self.__product_restarting_flag

    @restart_flag.setter
    def restart_flag(self, value):
        with self.__mutex:
            self.__product_restarting_flag = value

    def request_product_info(self):
        self.__mutex.acquire()
        try:
            response, code = self.run_command('--app-info --json', ignore_code=True)
            if code != 127 and code != 64 and len(response) != 0:
                self.__product_info = ProductInfoScheme.parse_raw(response)
                self.__product_avail_flag = True
            else:
                self.__product_info = ProductInfoScheme()
                self.__product_avail_flag = False
        finally:
            self.__mutex.release()

    def calculate_product_status(self, forced: bool = True):
        if forced:
            self.request_product_info()
        validation_info = []
        if self.__product_restarting_flag:
            validation_info.append('KESL restarting')
        elif not self.__product_avail_flag:
            validation_info.append('KESL not response')
        else:
            if not self.__product_info.databases_loaded:
                validation_info.append('Databases not loaded')
            if self.__product_info.license_info != 'The key is valid':
                validation_info.append(f'License error: {self.__product_info.license_info}')
        return len(validation_info) == 0, validation_info

    def create_product_info(self, forced: bool = True):
        product_avail, reason = self.calculate_product_status(forced)
        response = {
            'status': 'service available' if product_avail else 'service not available',
            'product info': self.__product_info.dict()
        }
        if not product_avail:
            response['status_reason'] = reason
        return response
