'''
This class encapsulates the complexity of the Security Finding that is present in application profiles and specific builds.

It has constructors and comparison functions to handle findings in both JSON and XML format.
'''
import json
import xmltodict


class Finding:
    def __init__(self, dictionary):
        if 'dict' in str(type(dictionary)):
            self.dictionary = dictionary
            # Iterate over dictionary keys and assign instance variables with key-->value pairs
            for key, value in dictionary.items():
                setattr(self, key, value)
        else:
            self.dictionary = {}
            print("bad value passed to Finding constructor")

    @classmethod
    def from_xml(cls, xml_finding):
        dictionary = xmltodict.parse(xml_finding)
        # Need to fix up the dictionary keys to match JSON keys before instantiating the Finding object
        return cls(dictionary)

    @classmethod
    def from_json(cls, json_finding):
        dictionary = json.loads(json_finding)
        return cls(dictionary)

    def to_json(self):
        '''
        This method returns a JSON string representing the Finding
        :return: json_finding
        '''
        pass

    def print(self):
        print_string = ""
        instance_variables = self.dictionary
        for dict_key in instance_variables:
            print_string += "Instance variable {} has value {} ".format(dict_key, getattr(self, dict_key))
            # print("Instance variable key: {}".format(dict_key))
            # print("Instance variable value: {}".format(getattr(self, dict_key)))
        return print_string