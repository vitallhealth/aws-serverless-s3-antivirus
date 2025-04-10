import sys
import boto3
from botocore.exceptions import ClientError
import logging
import os
import subprocess
from pathlib import Path

PDFID_PATH = "/opt/pdfid/pdfid.py"

ALLOWED_UPLOAD_ARGS = [
    "ACL",
    "CacheControl",
    "ChecksumAlgorithm",
    "ContentDisposition",
    "ContentEncoding",
    "ContentLanguage",
    "ContentType",
    "ExpectedBucketOwner",
    "Expires",
    "GrantFullControl",
    "GrantRead",
    "GrantReadACP",
    "GrantWriteACP",
    "Metadata",
    "ObjectLockLegalHoldStatus",
    "ObjectLockMode",
    "ObjectLockRetainUntilDate",
    "RequestPayer",
    "ServerSideEncryption",
    "StorageClass",
    "SSECustomerAlgorithm",
    "SSECustomerKey",
    "SSECustomerKeyMD5",
    "SSEKMSKeyId",
    "SSEKMSEncryptionContext",
    "Tagging",
    "WebsiteRedirectLocation",
    "ChecksumType",
    "MpuObjectSize",
    "ChecksumCRC32",
    "ChecksumCRC32C",
    "ChecksumCRC64NVME",
    "ChecksumSHA1",
    "ChecksumSHA256",
]

s3_client = boto3.client("s3")


def scan_pdf(path: str) -> bool:
    """Scan a PDF file for suspicious keywords

    :param path: Path to the file to scan
    :return: True if no suspicious content was found. False otherwise
    """
    print(f"Scanning {path} for embedded scripts...")
    result = subprocess.run(
        ["python", PDFID_PATH, path],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if result.returncode != 0:
        print("pdfid failed:", result.stderr)
        return False

    suspicious_keywords = ["/JavaScript", "/JS", "/OpenAction", "/Launch", "/AA"]
    for line in result.stdout.splitlines():
        for key in suspicious_keywords:
            if line.strip().startswith(key):
                count = int(line.strip().split()[-1])
                if count > 0:
                    print(f"Suspicious element detected: {key} ({count})")
                    return False
    print("No embedded scripts found.")
    return True


def sanitize_pdf(input_path: str, output_path: str) -> None:
    """Sanitize a PDF

    Creates a new, sanitized PDF at `output_path`

    **DO NOT PROVIDE THE SAME VALUE FOR `input_path` AND `output_path`. WILL CORRUPT PDF.**

    Removes /JavaScript, /OpenAction, /Launch, etc. from PDF files

    :param input_path: Path to the input file
    :param output_path: Where to write the output file
    """
    print(f"Sanitizing {input_path} -> {output_path}")
    result = subprocess.run(
        [
            "gs",
            "-sDEVICE=pdfwrite",
            "-dSAFER",
            "-dNOPAUSE",
            "-dBATCH",
            f"-sOutputFile={output_path}",
            input_path,
        ]
    )
    if result.returncode == 0:
        print("Sanitized PDF written.")
    else:
        print("Ghostscript failed to sanitize.")
        raise result.stderr


def upload_file(
    file_name: str, bucket: str, object_name: str = None, ExtraArgs: dict = None
) -> bool:
    """Upload a file to an S3 bucket

    :param file_name: File to upload
    :param bucket: Bucket to upload to
    :param object_name: S3 object name. If not specified then file_name is used
    :return: True if file was uploaded, else False
    """

    # If S3 object_name was not specified, use file_name
    if object_name is None:
        object_name = os.path.basename(file_name)

    # Upload the file
    s3_client = boto3.client("s3")
    try:
        response = s3_client.upload_file(
            file_name, bucket, object_name, ExtraArgs=ExtraArgs
        )
    except ClientError as e:
        logging.error(e)
        return False
    return True


def notify_about_tainted_file(bucket: str, key: str) -> None:
    """Send a notification about a tainted file

    :param bucket: S3 Bucket where the tainted file is located
    :param key: S3 Key of the tainted file
    """
    sns_client = boto3.client("sns")
    sns_topic_arn = os.environ.get("snsTopicArn")
    if bool(sns_topic_arn):
        try:
            print(f"Sending SNS notification to {sns_topic_arn}.")
            response = sns_client.publish(
                TopicArn=sns_topic_arn,
                Message=f"Infected file found: s3://{bucket}/{key}",
            )
            print(f"Sent SNS notification. MessageId: {response['MessageId']}")
        except Exception as e:
            print(f"Failed to send SNS notification")
            logging.error(e)


def lambda_handler(event, context):
    bucket = None
    key = None

    try:
        bucket = event["detail"]["requestParameters"]["bucketName"]
        key = event["detail"]["requestParameters"]["key"]
        file_name = "/tmp/" + key.split("/")[-1]

        # Updating the object's scan status to in progress
        tag_response = s3_client.put_object_tagging(
            Bucket=bucket,
            Key=key,
            # versionId=version,
            Tagging={"TagSet": [{"Key": "ScanStatus", "Value": "InProgress"}]},
        )

        s3_client.download_file(bucket, key, file_name)

        head_response = s3_client.head_object(Bucket=bucket, Key=key)
        content_type = head_response["ContentType"]

        ### PDF specific logic for sanitization ###
        if content_type == "application/pdf":
            input_pdf = Path(file_name)
            output_pdf = input_pdf.with_name(
                f"{input_pdf.stem}_sanitized.pdf"
            )  # Location of sanitized file to create

            scan_pdf(
                input_pdf
            )  # Detects suspicious (non-virus) content. Nothing more. Could use for additional tagging at end of process
            sanitize_pdf(input_pdf, output_pdf)  # Creates a new PDF at output_pdf

            # Copy metadata from original file
            extra_args = {
                k: v for k, v in head_response.items() if k in ALLOWED_UPLOAD_ARGS
            }
            upload_file(
                output_pdf, bucket, key, ExtraArgs=extra_args
            )  # Replace file in bucket with sanitized one
            # Set file_name to sanitized one, continue with scan
            file_name = output_pdf

        scan_cmd = f"clamscan --quiet {file_name}"
        sp = subprocess.Popen(
            scan_cmd,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True,
        )

        out, err = sp.communicate()

        # * clamscan return values (documented from man clamscan)
        # *  0 : No virus found.
        # *  1 : Virus(es) found.
        # * 40: Unknown option passed.
        # * 50: Database initialization error.
        # * 52: Not supported file type.
        # * 53: Can't open directory.
        # * 54: Can't open file. (ofm)
        # * 55: Error reading file. (ofm)
        # * 56: Can't stat input file / directory.
        # * 57: Can't get absolute path name of current working directory.
        # * 58: I/O error, please check your file system.
        # * 62: Can't initialize logger.
        # * 63: Can't create temporary files/directories (check permissions).
        # * 64: Can't write to temporary directory (please specify another one).
        # * 70: Can't allocate memory (calloc).
        # * 71: Can't allocate memory (malloc).

        return_code = sp.wait()

        if return_code == 0:
            print("Clean file found, updating the object with scan status tags...")
            # Update tags with scan status
            tag_response = s3_client.put_object_tagging(
                Bucket=bucket,
                Key=key,
                # versionId=version,
                Tagging={
                    "TagSet": [
                        {"Key": "ScanStatus", "Value": "Completed"},
                        {"Key": "Tainted", "Value": "No"},
                    ]
                },
            )
        elif return_code == 1:
            preferredAction = os.environ.get("preferredAction")
            print(
                "Infected file found. Performing '"
                + preferredAction
                + "' action on the file..."
            )

            if preferredAction == "Delete":
                delete_response = s3_client.delete_object(
                    Bucket=bucket,
                    Key=key,
                    # VersionId=version
                )
                print("Deleting the infected file. Response: " + str(delete_response))
            else:
                tag_response = s3_client.put_object_tagging(
                    Bucket=bucket,
                    Key=key,
                    # versionId=version,
                    Tagging={
                        "TagSet": [
                            {"Key": "ScanStatus", "Value": "Completed"},
                            {"Key": "Tainted", "Value": "Yes"},
                        ]
                    },
                )

                print("Tagging the infected file. Response: " + str(tag_response))
            # Deliver notifications about the tainted file
            notify_about_tainted_file(bucket, key)
        else:
            print(f"Unknown error occured while scanning the {key} for viruses.")
            tag_response = s3_client.put_object_tagging(
                Bucket=bucket,
                Key=key,
                # versionId=version,
                Tagging={
                    "TagSet": [
                        {"Key": "ScanStatus", "Value": "Error"},
                        {"Key": "Tainted", "Value": "Unknown"},
                    ]
                },
            )

    except Exception as e:
        print(f"Unknown error occured while scanning the {key} for viruses.")
        logging.error(e)
        tag_response = s3_client.put_object_tagging(
            Bucket=bucket,
            Key=key,
            # versionId=version,
            Tagging={
                "TagSet": [
                    {"Key": "ScanStatus", "Value": "Error"},
                    {"Key": "Tainted", "Value": "Unknown"},
                ]
            },
        )
