import json
import os
import boto3
from boto3.dynamodb.types import TypeDeserializer, TypeSerializer

def serialize(python_dict):
    serializer = TypeSerializer()
    return {k: serializer.serialize(
        v) for k, v in python_dict.items()}

def deserialize(low_level_data):
    deserializer = TypeDeserializer()
    return {k: deserializer.deserialize(
        v) for k, v in low_level_data.items()}

def get_packages_vulns( table_name, last_modified=0):
    dynamoclient = boto3.client('dynamodb', region_name='us-east-1',
                        aws_access_key_id = '',
                        aws_secret_access_key = '',
                        aws_session_token = ''
    )
    mr_values = []
    paginator = dynamoclient.get_paginator('scan')
    for page in paginator.paginate(TableName=table_name):
        for item in page.get('Items', []):
            if 'vulns' in item:
                vulns_data = item['vulns']['M']
                for cve_details in vulns_data.items():
                    if 'AQUA' not in cve_details[0]:
                        if 'L' in cve_details[1]:
                            for entry in cve_details[1]['L']:
                                if 'M' in entry and 'mr' in entry['M']:
                                    mr_value = entry['M']['mr']['N']
                                    if(mr_value == '5'):
                                        mr_values.append([item['package_name'], cve_details])
    print(mr_values)
    print(len(mr_values))

    output_file_path = "cves_with_mr5.json"
    with open(output_file_path, 'w') as json_file:
        json.dump(mr_values, json_file, indent=4)
    print(f"DynamoDB items saved to {output_file_path}")

get_packages_vulns("vulnerable_packages-4Prod")
