# suggestion from Amit K: xception raise with details on what is the overlap
# take excel as an input for validating

import argparse
from ipaddress import ip_network
import pandas

FW_MASTER_SHEET = "M1K - FW Rule - Tracker.xlsx"
SOURCE_DESC_COLUMN_NAME = "Source IP Description"
SOURCE_IP_COLUMN_NAME = "Source IP"
DEST_DESC_COLUMN_NAME = "Destination IP Description"
DEST_IP_COLUMN_NAME = "Destination IP"
PROTOCOL_COLUMN_NAME = "Protocol"
PORT_COLUMN_NAME = "Port"
FLOW_DESC_COLUMN_NAME = "Flow Description"
REQUESTER_COLUMN_NAME = "Requester"
STATUS_COLUMN_NAME = "Status"
AZURE_SUPERNET_RANGES = [
    "10.200.0.0/16",
    "10.201.0.0/16",
    "10.202.0.0/16",
    "10.203.0.0/16"
]

# Lambda function to build existing rules from the excel name passed
build_existing_rules = lambda excel_name: pandas.read_excel(excel_name)


def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('--source_ip', required=True, help="source ip")
    parser.add_argument('--destination_ip', required=True, help="destination ip")
    parser.add_argument('--protocol', required=True, help="protocol")
    parser.add_argument('--destination_port', required=True, help="destination port. Comma seperated values accepted.")
    return parser.parse_args()


def is_azure_to_azure_communication(rule_to_validate):
    is_source_subnet_of_azure_ranges = False
    is_destination_subnet_of_azure_ranges = False
    for network_range in AZURE_SUPERNET_RANGES:
        is_source_subnet_of_azure_ranges = ip_network(rule_to_validate.source_ip).subnet_of(ip_network(network_range))
        is_source_subnet_of_azure_ranges = ip_network(rule_to_validate.destination_ip).subnet_of(ip_network(network_range))

        if is_source_subnet_of_azure_ranges and is_source_subnet_of_azure_ranges:
            return True
    return False


def does_rule_matches_arg(rule_to_validate, fw_dataset_rule):
    is_source_overlapping = ip_network(rule_to_validate.source_ip).subnet_of(ip_network(fw_dataset_rule[SOURCE_IP_COLUMN_NAME]))
    is_destination_overlapping = ip_network(rule_to_validate.destination_ip).subnet_of(ip_network(fw_dataset_rule[DEST_IP_COLUMN_NAME]))
    is_protocol_same = rule_to_validate.protocol.lower() == fw_dataset_rule[PROTOCOL_COLUMN_NAME].lower()
    is_port_same = False
    for port_number in rule_to_validate.destination_port:
        if port_number in fw_dataset_rule[PORT_COLUMN_NAME]:
            is_port_same = True

    return (is_source_overlapping and
            is_destination_overlapping and
            is_protocol_same and
            is_port_same)


def firewall_request_validator():
    try:
        # build args
        args = get_args()

        # Create list of ports in integer from from string
        args.destination_port = [int(port) for port in args.destination_port.split(",")]

        # build existing rules set from the master firewall sheet. Convert to list of dict.
        fw_dataset = build_existing_rules(FW_MASTER_SHEET).to_dict(orient="records")

        # Loop through each element of firewall dataset and see if that matches with args rule
        for fw_dataset_rule in fw_dataset:
            # Convert comma seperated port numbers to list of integers before matching
            fw_dataset_rule[PORT_COLUMN_NAME] = [int(port) for port in fw_dataset_rule[PORT_COLUMN_NAME].split(",")]

            # Get final result match
            result = does_rule_matches_arg(args, fw_dataset_rule)
            if result:
                raise Exception(f"Overlap exists with rule :{fw_dataset_rule}")

        print("No overlap exists. Validating if Azure to Azure Communication.")

        if is_azure_to_azure_communication(args):
            raise Exception(f"The source and destination both belong to Azure ranges :{AZURE_SUPERNET_RANGES}, Not allowed to implement")

        print ("Not a Azure to Azure communication.\r\n\r\nCan be allowed!!!")

    except Exception as e:
        print (f"Exception raised:{e}")
        raise

if __name__ == "__main__":
    firewall_request_validator()
