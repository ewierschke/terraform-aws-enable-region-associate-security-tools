"""Associate member account security tools to Security Tooling Account for newly enabled opt-in region.

Purpose:
    In an AWS SRA Organizations environment, associate member account security tools
    Detective, Inspector, and Macie to Security tooling account instances
    Enabling Opt-In region after Security tooling account instances are created does not
    currently allow automatically joining to tools as tool settings only apply to 
    *new* organizations member accounts
Permissions:
    ** Management Account (Executing Account)
    * organizations:DescribeAccount
    ** Security Tooling account (Assumed Role)
    * detective:ListGraphs
    * detective:CreateMembers
    * detective:StartMonitoringMember
    * inspector2:AssociateMember
    * inspector2:Enable
    * macie2:CreateMember
Environment Variables:
    LOG_LEVEL: (optional): sets the level for function logging
            supported values:
            critical, error, warning, info (default)
    DRY_RUN: (optional): true or false, defaults to true
    sets whether the delete should be performed,
    otherwise just log the actions that would be taken
    ASSUME_ROLE_NAME: Name of role to assume
    MAX_WORKERS: (optional) # of workers to process resources, default 20

"""

from argparse import ArgumentParser, RawDescriptionHelpFormatter
import collections
import concurrent.futures
import logging
import os
import sys

import boto3
from aws_assume_role_lib import (  # type: ignore
    assume_role,
    generate_lambda_session_name,
)

# Standard logging config
DEFAULT_LOG_LEVEL = logging.INFO
LOG_LEVELS = collections.defaultdict(
    lambda: DEFAULT_LOG_LEVEL,
    {
        "CRITICAL": logging.CRITICAL,
        "ERROR": logging.ERROR,
        "WARNING": logging.WARNING,
        "INFO": logging.INFO,
        "DEBUG": logging.DEBUG,
    },
)

# Lambda initializes a root logger that needs to be removed in order to set a
# different logging config
root = logging.getLogger()
if root.handlers:
    for handler in root.handlers:
        root.removeHandler(handler)

logging.basicConfig(
    format="%(asctime)s.%(msecs)03dZ [%(name)s][%(levelname)s]: %(message)s ",
    datefmt="%Y-%m-%dT%H:%M:%S",
    level=LOG_LEVELS[os.environ.get("LOG_LEVEL", "").upper()],
)

log = logging.getLogger(__name__)

ASSUME_ROLE_NAME = os.environ.get("ASSUME_ROLE_NAME", "OrganizationAccountAccessRole")
#unused?
DRY_RUN = os.environ.get("DRY_RUN", "true").lower() == "true"
ENABLE_DETECTIVE = os.environ.get("ENABLE_DETECTIVE", 1)
ENABLE_INSPECTOR = os.environ.get("ENABLE_INSPECTOR", 1)
ENABLE_MACIE = os.environ.get("ENABLE_MACIE", 1)
#unused?
MAX_WORKERS = int(os.getenv("MAX_WORKERS", "20"))
SECURITY_TOOLING_ACCOUNT_ID = os.environ.get("SECURITY_TOOLING_ACCOUNT_ID", "123456789012")

# Get the Lambda session in the lambda context
SESSION = boto3.Session()


class AddSecurityToolError(Exception):
    """Add Security Tool Error."""


def lambda_handler(event, context):  # pylint: disable=unused-argument, too-many-locals
    """Delete Default VPC in all regions.

    Assumes role to security tooling account and associates security tools for event triggered account for specified region
    Entrypoint if triggered via lambda
    """
    log.debug("AWS Event: %s", event)

    event_data = parse_event(event)
    log.info("Parsed event data: %s", event_data)

    assume_role_arn = (
        f"arn:{get_partition()}:iam::{SECURITY_TOOLING_ACCOUNT_ID}:role/{ASSUME_ROLE_NAME}"
    )

    main(event_data["account_id"], SECURITY_TOOLING_ACCOUNT_ID, assume_role_arn, event_data["regions"])


def get_enable_region_account_id(event):
    """Return account id for enable region events."""
    return event["detail"].get("accountId") or event["account"]


def get_region_opt_in_regions(event):
    """Return region name for region opt-in events."""
    return [event["detail"]["regionName"]]


def parse_event(event):
    """Return event data for supported events."""
    event_name_strategy = {
        "Region Opt-In Status Change": lambda x: "EnableOptInRegion",
    }

    account_id_strategy = {
        "EnableOptInRegion": get_enable_region_account_id,
    }

    regions_strategy = {
        "EnableOptInRegion": get_region_opt_in_regions,
    }

    event_name = event_name_strategy[event["detail-type"]](event)

    return {
        "account_id": account_id_strategy[event_name](event),
        "regions": regions_strategy[event_name](event),
    }


def get_assumed_role_session(account_id, role_arn):
    """Get boto3 session."""
    function_name = os.environ.get(
        "AWS_LAMBDA_FUNCTION_NAME", os.path.basename(__file__)
    )

    role_session_name = generate_lambda_session_name(function_name)

    # Assume the session
    assumed_role_session = assume_role(
        SESSION, role_arn, RoleSessionName=role_session_name, validate=False
    )
    # do stuff with the assumed role using assumed_role_session
    log.debug(
        "Assumed identity for account %s is %s",
        account_id,
        assumed_role_session.client("sts").get_caller_identity()["Arn"],
    )
    return assumed_role_session


def get_partition():
    """Return AWS partition."""
    sts = boto3.client("sts")
    return sts.get_caller_identity()["Arn"].split(":")[1]


def get_regions(assumed_role_session):
    """Build a region list."""
    client = assumed_role_session.client("ec2")
    regions = client.describe_regions()
    return [region["RegionName"] for region in regions["Regions"]]


def get_tools_to_enable():
    """Get tools to enable from Env vars."""
    tools = []

    if ENABLE_DETECTIVE:
        tools.append("detective")
    if ENABLE_INSPECTOR:
        tools.append("inspector")
    if ENABLE_MACIE:
        tools.append("macie")

    log.info("Get tools to enable from Environment Vars")
    return tools


def add_to_detective(acct, assumed_role_session):
    """Add to Detective."""
    """Assumes only a single graph per region exists in security tooling account"""
    region=acct["region"]
    detective_client = assumed_role_session.client("detective", region_name=region)
    log.info("Getting existing detective graph for account: %s", acct["account_id"])
    graph_response = detective_client.list_graphs(
            MaxResults=123
    )
    log.info("Adding account %s to detective", acct["account_id"])
    log.info(graph_response)
    graph_arn=graph_response["GraphList"]["Arn"]
    create_member_response = detective_client.create_members(
        GraphArn=graph_arn,
        Message='Lambda in Mgmt Acct Adding member to Detective Graph',
        DisableEmailNotification=True,
        Accounts=[
            {
                'AccountId': acct["account_id"],
                'EmailAddress': acct["account_email"]
            },
        ]
    )
    log.info(create_member_response)
    start_monitoring_response = detective_client.start_monitoring_member(
        GraphArn=graph_arn,
        AccountId=acct["account_id"]
    )
    log.info(start_monitoring_response)


def add_to_inspector(acct, assumed_role_session):
    """Add to Inspector."""
    region=acct["region"]
    inspector2_client = assumed_role_session.client("inspector2", region_name=region)
    log.info("Associating account member account %s to inspector", acct["account_id"])    
    response = inspector2_client.associate_member(
        accountId=acct["account_id"]
    )
    log.info(response)
    log.info("Enabling inspector for account: %s", acct["account_id"])
    """LAMBDA_CODE scanning only currently supported in select regions"""
    enable_response = inspector2_client.enable(
        accountIds=[
            acct["account_id"],
        ],
        clientToken='idempotencystring',
        resourceTypes=[
            'EC2'|'ECR'|'LAMBDA',
        ]
    )
    log.info(enable_response)


def add_to_macie(acct, assumed_role_session):
    """Add to Macie."""
    region=acct["region"]
    macie2_client = assumed_role_session.client("macie2", region_name=region)
    log.info("Create member account %s for macie", acct["account_id"])
    response = macie2_client.create_member(
        account={
            'accountId': acct["account_id"],
            'email': acct["account_email"]
        },
        # tags={
        #     'string': 'string'
        # }
    )
    log.info(response)


def account_associate_all_tools(account_id, account_email, security_tool, region, assumed_role_session):
    """Do the work - order of operation.

    1.) try to add to detective
    2.) try to add to inspector
    3.) try to add to macie

    """
    exception_list = []

    log.info("Adding account_id %s to security tool %s started", account_id, security_tool)
    acct = {
        "account_id": account_id,
        "account_email": account_email,
        "region": region,
        "session": assumed_role_session,
    }

    if security_tool == "detective":
        try:
            add_to_detective(acct, assumed_role_session)
        except BaseException as exc:  # pylint: disable=broad-except
            # Allow threads to continue on exception, but capture the error
            exception_list.append(process_tool_exception(acct, "add_to_detective", exc))

    if security_tool == "inspector":
        try:
            add_to_inspector(acct, assumed_role_session)
        except BaseException as exc:  # pylint: disable=broad-except
            # Allow threads to continue on exception, but capture the error
            exception_list.append(process_tool_exception(acct, "add_to_inspector", exc))

    if security_tool == "macie":
        try:
            add_to_macie(acct, assumed_role_session)
        except BaseException as exc:  # pylint: disable=broad-except
            # Allow threads to continue on exception, but capture the error
            exception_list.append(process_tool_exception(acct, "add_to_macie", exc))

    if exception_list:
        exception_list = "\r\r ".join(exception_list)
        exception_str = (
            f"Exceptions for Account: {acct['account_id']} "
            f"Region: {acct['region']} Tool: {security_tool}:\r{exception_list}"
        )
        log.error(exception_str)
        raise AddSecurityToolError(Exception(exception_str))


def get_error_prefix(account_id, region, method_name):
    """Get prefix for error message."""
    return f"Account: {account_id}\r Region: {region}\r Method: {method_name}"


def convert_tool_exception_to_string(account_id, region, method_name, msg, exception):
    """Convert exception to string."""
    error_str = get_error_prefix(account_id, region, method_name)
    if msg:
        error_str = f"{error_str}\r Error:{msg}\r"
    error_str = f"{error_str}\r Exception:{exception}"
    return error_str


def process_tool_exception(acct, method_name, exception):
    """Handle exceptions and return error string."""
    error_str = convert_tool_exception_to_string(
        acct["account_id"], acct["region"], method_name, None, exception
    )

    log.error(error_str)
    log.exception(exception)

    return error_str


def cli_main(member_account_id, security_tooling_account_id, assume_role_arn=None, assume_role_name=None, region=None):
    """Process cli assume_role_name arg and pass to main."""
    log.debug(
        "CLI - member_account_id=%s assume_role_arn=%s assume_role_name=%s, region=%s",
        member_account_id,
        assume_role_arn,
        assume_role_name,
        region,
    )

    if assume_role_name:
        assume_role_arn = (
            f"arn:{get_partition()}:iam::{security_tooling_account_id}:role/{assume_role_name}"
        )
        log.info("assume_role_arn for provided role name is '%s'", assume_role_arn)

    if SECURITY_TOOLING_ACCOUNT_ID:
        security_tooling_account_id = SECURITY_TOOLING_ACCOUNT_ID

    main(member_account_id, security_tooling_account_id, assume_role_arn, regions=region)


def main(member_account_id, security_tooling_account_id, assume_role_arn, regions):
    """Assume role and non-concurrently enable security tools."""
    log.debug(
        "Main identity is %s",
        SESSION.client("sts").get_caller_identity()["Arn"],
    )

    """Use Organizations client to get account email address"""
    org_client = SESSION.client("organizations", region_name=regions)
    response = org_client.describe_account(
        AccountId=member_account_id
    )
    member_account_email=response['Account']['Email']

    assumed_role_session = get_assumed_role_session(security_tooling_account_id, assume_role_arn)

    regions = regions or get_regions(assumed_role_session)

    exception_list = non_concurrently_associate_security_tools(
        assumed_role_session,
        member_account_id,
        member_account_email,
        regions,
    )

    if exception_list:
        exception_list = "\r\r ".join(exception_list)
        exception_str = f"All Exceptions encountered:\r\r{exception_list}\r\r"
        log.error(exception_str)
        raise AddSecurityToolError(Exception(exception_str))

    if DRY_RUN:
        log.debug("Dry Run listed all resources that would be deleted")
    else:
        log.debug("Added account to selected security tools")


def non_concurrently_associate_security_tools(
    assumed_role_session,
    target_account_id,
    target_account_email,
    regions,
):
    """Create worker threads and add security tools."""
    """Security tools do not have resource clients to enable thread safety"""
    exception_list = []
    futures = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            try:
                tool_names = get_tools_to_enable()
            except BaseException as exc:  # pylint: disable=broad-except
                # Allow threads to continue on exception, but capture the erro
                msg = "Error: Error getting tools to enable"
                exception_list.append(
                    convert_tool_exception_to_string(
                        target_account_id,
                        regions,
                        lambda_handler.__name__,
                        msg,
                        exc,
                    )
                )
                log.exception(exc)

            for tool in tool_names:
                log.info(
                    "Processing Account: %s with Email %s Region: %s and tool name: %s",
                    target_account_id,
                    target_account_email,
                    regions,
                    tool,
                )
                try:
                    # futures.append(executor.submit(account_associate_all_tools, need_resource_client, regions))
                    account_associate_all_tools(target_account_id, target_account_email, tool, regions, assumed_role_session)

                except BaseException as exc:  # pylint: disable=broad-except
                    # Allow threads to continue on exception, but capture the error
                    msg = "Error: Exception submitting del_vpc_all executor"
                    exception_list.append(
                        convert_tool_exception_to_string(
                            target_account_id,
                            regions,
                            lambda_handler.__name__,
                            msg,
                            exc,
                        )
                    )
                    log.exception(exc)
    concurrent.futures.wait(futures)
    for fut in futures:
        try:
            fut.result()
        except BaseException as exc:  # pylint: disable=broad-except
            # Allow threads to continue on exception, but capture the error
            exception_list.append(str(exc))

    return exception_list


if __name__ == "__main__":

    def create_args():
        """Return parsed arguments."""
        parser = ArgumentParser(
            formatter_class=RawDescriptionHelpFormatter,
            description="""
Associate member account security tools to Security Tooling Account for newly enabled opt-in region.

Supported Environment Variables:
    'LOG_LEVEL': defaults to 'info'
        - set the desired log level ('error', 'warning', 'info' or 'debug')

    'DRY_RUN': defaults to 'true'
        - set whether actions should be simulated or live
        - value of 'true' (case insensitive) will be simulated.

    'MAX_WORKERS': defaults to '20'
        -sets max number of worker threads to run simultaneously.
""",
        )
        required_args = parser.add_argument_group("required named arguments")
        required_args.add_argument(
            "--member-account-id",
            required=True,
            type=str,
            help="Member account number",
        )
        required_args.add_argument(
            "--security-tooling-account-id",
            required=True,
            type=str,
            help="Security Tooling account number to associate member account to",
        )
        required_args.add_argument(
            "--region",
            required=True,
            type=str,
            help="Region name to associate security tools in",
        )
        mut_x_group = parser.add_mutually_exclusive_group(required=True)
        mut_x_group.add_argument(
            "--assume-role-arn",
            type=str,
            help="ARN of IAM role to assume in the target account (case sensitive)",
        )
        mut_x_group.add_argument(
            "--assume-role-name",
            type=str,
            help="Name of IAM role to assume in the target account (case sensitive)",
        )

        return parser.parse_args()

    sys.exit(cli_main(**vars(create_args())))
