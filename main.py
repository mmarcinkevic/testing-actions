import argparse

def main(arguments):
    print(f"Email Address Reporter: {arguments.email_address_reporter}")
    print(f"Email Address Other: {arguments.email_address_other}")
    print(f"Access For: {arguments.access_for}")
    print(f"Requested Okta Groups: {arguments.requested_okta_groups}")
    print(f"Asset Messages: {arguments.asset_messages}")
    print(f"Access Type: {arguments.accesstype}")
    print(f"Requested Custom Groups: {arguments.requested_custom_groups}")
    print(f"Issue Key: {arguments.issue_key}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--email-address-reporter")
    parser.add_argument("--email-address-other")
    parser.add_argument("--access-for")
    parser.add_argument("--requested-okta-groups")
    parser.add_argument("--asset-messages")
    parser.add_argument("--accesstype")
    parser.add_argument("--requested-custom-groups")
    parser.add_argument("--issue-key")

    args = parser.parse_args()
    main(args)
