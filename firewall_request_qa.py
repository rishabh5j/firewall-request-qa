import argparse
from ipaddress import ip_network
import pandas

FW_MASTER_SHEET = "M1K - FW Rule - Tracker.xlsx"
RESULT_SHEET_NAME = "Result.xlsx"
MASTER_SHEET_NAME = "MasterProtected"
FW_WORKSHEET_TO_VALIDATE = "FirewallRulesToValidate"
SERIAL_NUMBER_COLUMN_NAME = "SerialNo"
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
build_existing_rules = lambda excel_name, sheet_name: pandas.read_excel(excel_name, sheet_name)


def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('--source_ip', required=True, help="source ip")
    parser.add_argument('--destination_ip', required=True, help="destination ip")
    parser.add_argument('--protocol', required=True, help="protocol")
    parser.add_argument('--destination_port', required=True, help="destination port. Comma seperated values accepted.")
    return parser.parse_args()


def is_azure_to_azure_communication(fw_rule_to_be_validated):
    is_source_subnet_of_azure_ranges = False
    is_destination_subnet_of_azure_ranges = False
    for network_range in AZURE_SUPERNET_RANGES:
        is_source_subnet_of_azure_ranges = ip_network(fw_rule_to_be_validated[SOURCE_IP_COLUMN_NAME]).subnet_of(ip_network(network_range))
        is_source_subnet_of_azure_ranges = ip_network(fw_rule_to_be_validated[DEST_IP_COLUMN_NAME]).subnet_of(ip_network(network_range))

        if is_source_subnet_of_azure_ranges and is_source_subnet_of_azure_ranges:
            return True
    return False


def does_rule_matches_arg(rule_to_validate, fw_dataset_rule):
    print(f"matching {rule_to_validate} againts {fw_dataset_rule}")
    is_source_overlapping = ip_network(rule_to_validate[SOURCE_IP_COLUMN_NAME]).subnet_of(ip_network(fw_dataset_rule[SOURCE_IP_COLUMN_NAME]))
    is_destination_overlapping = ip_network(rule_to_validate[DEST_IP_COLUMN_NAME]).subnet_of(ip_network(fw_dataset_rule[DEST_IP_COLUMN_NAME]))
    is_protocol_same = rule_to_validate[PROTOCOL_COLUMN_NAME].lower() == fw_dataset_rule[PROTOCOL_COLUMN_NAME].lower()
    is_port_same = False
    for port_number in rule_to_validate[PORT_COLUMN_NAME]:
        if port_number in fw_dataset_rule[PORT_COLUMN_NAME]:
            is_port_same = True

    return (is_source_overlapping and
            is_destination_overlapping and
            is_protocol_same and
            is_port_same)

def verify_firewall_rule_overlap(fw_rule_to_be_validated, fw_dataset):
    # Loop through each element of firewall dataset and see if that matches with args rule
    for fw_dataset_rule in fw_dataset:

        # Get final result match
        result = does_rule_matches_arg(fw_rule_to_be_validated, fw_dataset_rule)
        if result:
            print(f"\r\nOverlap with rule at SerialNo:{fw_dataset_rule[SERIAL_NUMBER_COLUMN_NAME]}\r\n"),
            return f"Overlap with rule at SerialNo:{fw_dataset_rule[SERIAL_NUMBER_COLUMN_NAME]}"
    return None

def format_console_output():
    print ("\r\n" + "+-"*50 + "\r\n")

def firewall_request_validator():
    try:
        # Build dataframe for firewall rules to be validated
        dataset_to_be_validated = build_existing_rules(FW_MASTER_SHEET, FW_WORKSHEET_TO_VALIDATE)
        fw_dataset_to_be_validated = dataset_to_be_validated.to_dict(orient="records")
        new_dataset_with_result = dataset_to_be_validated
        new_dataset_with_result["Results"] = ""

        # build existing rules set from the master firewall sheet. Convert to list of dict.
        fw_dataset = build_existing_rules(FW_MASTER_SHEET, MASTER_SHEET_NAME).to_dict(orient="records")

        for fw_dataset_rule in fw_dataset:
            # Convert comma seperated port numbers to list of integers before matching
            fw_dataset_rule[PORT_COLUMN_NAME] = [int(port) for port in str(fw_dataset_rule[PORT_COLUMN_NAME]).split(",")]

        # track row number to write the final result in Result column
        row_number = -1
        for fw_rule_to_be_validated in fw_dataset_to_be_validated:
            row_number += 1

            # Format console output
            format_console_output()

            # Convert comma seperated port numbers to list of integers before matching
            fw_rule_to_be_validated[PORT_COLUMN_NAME] = [int(port) for port in str(fw_rule_to_be_validated[PORT_COLUMN_NAME]).split(",")]

            # Validate if the rule to be validated overlaps with any rule in MasterProtected sheet.
            does_firewall_rule_overlaps = verify_firewall_rule_overlap(fw_rule_to_be_validated, fw_dataset)
            if does_firewall_rule_overlaps:
                new_dataset_with_result.at[row_number, "Results"] = does_firewall_rule_overlaps
                continue

            print("\r\nNo overlap exists. Validating if Azure to Azure Communication.\r\n")

            if is_azure_to_azure_communication(fw_rule_to_be_validated):
                print(f"\r\nFor rule:{fw_rule_to_be_validated} The source and destination both belong to Azure ranges :{AZURE_SUPERNET_RANGES}. " +
                        "Not allowed to implement\r\n")
                new_dataset_with_result.at[row_number, "Results"] = f"Azure to Azure Communication not permitted."
                continue

            print ("Not a Azure to Azure communication.Can be allowed!!!")
            new_dataset_with_result.at[row_number, "Results"] = f"Can be requested"

        format_console_output()

        # Write the new dataset with result to new excel spreadsheet
        new_dataset_with_result.to_excel(RESULT_SHEET_NAME, index=False)

    except Exception as e:
        print (f"Exception raised:{e}")
        raise

if __name__ == "__main__":
    firewall_request_validator()
