import json
import boto3

def lang_Check(lang, temp):
    if('_java' in temp):
        lang[2] = lang[2] + 1
    elif ('_python' in temp):
        lang[3] = lang[3] + 1
    elif ('_csharp' in temp):
        lang[1] = lang[1] + 1
    elif ('_ruby' in temp):
        lang[5] = lang[5] + 1
    elif ('_nodejs' in temp):
        lang[7] = lang[7] + 1
    elif ('_php' in temp):
        lang[4] = lang[4] + 1
    elif ('_golang' in temp):
        lang[0] = lang[0] + 1
    elif ('_jslib' in temp):
        lang[6] = lang[6] + 1
                         # golang, csharp, java, python, php, ruby, jslib, nodejs


#function to find the latest table 
def Latest_Table():
    dynamoclient = boto3.client('dynamodb', region_name='us-east-1',
                        aws_access_key_id = 'ASIAYJ65BCN3DISOIBW7',
                        aws_secret_access_key = 'nbAtW9HWMDveYjV9QI6Jx2v2cNILuiB81g1uUbOa',
                        aws_session_token = 'IQoJb3JpZ2luX2VjELb//////////wEaCXVzLWVhc3QtMSJHMEUCIA5qRi8C64FUt44SB+pUHTLrzy5D0lOhlFH5LzILQoT5AiEA+o+SncOyjkkAj7jvWl+OlVPQXUjc7LN9OdbMmp8ouxEqmgMIzv//////////ARAAGgw1NzExNTczMjA1NjYiDIttShKrid9lKJWRDiruAnlM+iPa6mvwU7JyuA4qGfUBsdb5eQj5DO/uxoWwtXwi1UuQjcKMOvAjVG9jxntPVtJiYGuD3VR6qepKBnT8PgaLg6HcYS8gnfBkENInOlGD6NWUJVZUVOVg0cy9H0tEthSGwo8FYGbGpE7vftM3YI6V7+8Alg2FW2/66Lz6KoNrgOyrus/tDdkgOIA6VQitIUG0QGm2WkcP/yHfpS2yXmtGKBcb+S+LaKGNowUPgcZWV/NTVac4e4YEZkwXn4YYw8fviLKw3RiKiO4yzwhz05wwjwHLV5xAbGu9hPeuK3fzwc8kzndblqCvhNioNZltZA9M/VUTRtcsYUWN65viVTlkthfAJEKLSmGp7w/U7hqzmhjXMqkhqLhUM/A9I+QjtAIrPuYBoDWAfxXUSIRaX3PSFIfVFQ6DOcG8viSHfwfP5C6ryJIUEVJHFMHRviL8qbdVxJRmOP80NyXPisMFEzqeDLw2MgR/PyMwjdZ4jDD7lsipBjqmAelXcNfiHsHQ7Jc9dsPGvM3eLNMhco2k0di1O3mJdltz3sar1TbKTeq+Sbz/7iPJqELLZ9w4jxiKEPp4a2miLXDlNo713IDt37KVhwDyMtnLz+g2C24FF2X3LPq8M7nAB0CJFOR5UsI2J/tUkmIoejccJJQExfunErIvagd2E6zH5+sjJ9XAl6NxIsXnP3MLCPBVSgFAH/9faLpKRthjLrLMniY25dA='
    )
    paginator = dynamoclient.get_paginator('scan')
    response = dynamoclient.query(
        TableName= "aqua_source_metadataProd",
        KeyConditionExpression= "#parser_type = :parser_type",
        ExpressionAttributeNames= {
            '#parser_type': "parser_type"
        },
        ExpressionAttributeValues= {
            ':parser_type': {
                'S': "latest_table"
            }
        }
    )
    for item in response.get('Items', []):
        table = item['latest_vulnerability_package_table']['S']
    print(table)
    get_packages_vulns(table, paginator)




#function to find packages with Mr 5 and Src 4
def get_packages_vulns( table_name, paginator):
    mr_values = []
    src_4_data = []
    lang = [0, 0, 0, 0, 0, 0, 0, 0]
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
                                        if('src' in entry['M']):
                                            src_value = entry['M']['src']['N']
                                            if src_value == '4':
                                                src_4_data.append([item['package_name'], cve_details])
                                            else:
                                                mr_values.append([item['package_name'], cve_details])
                                                temp = item['package_name']['S']
                                                lang_Check(lang, temp)
                                        else:
                                            mr_values.append([item['package_name'], cve_details])
                                            temp = item['package_name']['S']
                                            lang_Check(lang, temp)
    print(len(mr_values))
    print(lang)
    print(len(src_4_data))

    output_file_path1 = "file_with_src4_mr5_data.json"
    with open(output_file_path1, 'w') as json_file:
        json.dump(src_4_data, json_file, indent=4)
    print(f"DynamoDB items saved to {output_file_path1}")

    output_file_path2 = "file_with_src!=4_mr5_data.json"
    with open(output_file_path2, 'w') as json_file:
        json.dump(mr_values, json_file, indent=4)
    print(f"DynamoDB items saved to {output_file_path2}")

Latest_Table()


