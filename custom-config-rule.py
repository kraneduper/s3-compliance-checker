import boto3
import logging
from botocore.exceptions import ClientError
from datetime import datetime

"""
REQUIRED IAM PERMISSIONS FOR LAMBDA EXECUTION ROLE:

The Lambda execution role needs the following permissions:

S3 Permissions:
- s3:ListAllMyBuckets          # To list all buckets in the account
- s3:GetBucketTagging          # To check if bucket has "Owner" tag
- s3:GetBucketPublicAccessBlock # To check public access block settings

AWS Config Permissions:
- config:PutEvaluations        # To submit evaluation results back to AWS Config

Example IAM Policy:
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "s3:ListAllMyBuckets",
                "s3:GetBucketTagging",
                "s3:GetBucketPublicAccessBlock"
            ],
            "Resource": "*"
        },
        {
            "Effect": "Allow",
            "Action": [
                "config:PutEvaluations"
            ],
            "Resource": "*"
        },
        {
            "Effect": "Allow",
            "Action": [
                "logs:CreateLogGroup",
                "logs:CreateLogStream",
                "logs:PutLogEvents"
            ],
            "Resource": "arn:aws:logs:*:*:*"
        }
    ]
}
"""

# Configure logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Initialize AWS clients
s3_client = boto3.client('s3')
config_client = boto3.client('config')


def evaluate_s3_bucket(bucket_name):
    """
    Evaluate a single S3 bucket for compliance.
    
    A bucket is compliant if:
    1. It has a tag key "Owner"
    2. Public access is fully blocked
    
    Args:
        bucket_name (str): Name of the S3 bucket to evaluate
        
    Returns:
        dict: Compliance result with compliance_type and annotation
    """
    compliance_type = 'COMPLIANT'
    annotation = ''
    issues = []
    
    try:
        # Check 1: Verify bucket has "Owner" tag
        logger.info(f"Checking tags for bucket: {bucket_name}")
        try:
            # Get bucket tagging
            tag_response = s3_client.get_bucket_tagging(Bucket=bucket_name)
            bucket_tags = tag_response.get('TagSet', [])
            
            # Check if "Owner" tag key exists
            has_owner_tag = any(tag.get('Key') == 'Owner' for tag in bucket_tags)
            
            if not has_owner_tag:
                issues.append("Missing 'Owner' tag")
                compliance_type = 'NON_COMPLIANT'
            else:
                # Get the Owner tag value for annotation
                owner_tag = next((tag for tag in bucket_tags if tag.get('Key') == 'Owner'), None)
                owner_value = owner_tag.get('Value', '') if owner_tag else ''
                logger.info(f"Bucket {bucket_name} has Owner tag with value: {owner_value}")
                
        except ClientError as e:
            error_code = e.response['Error']['Code']
            if error_code == 'NoSuchTagSet':
                # Bucket has no tags at all
                issues.append("Missing 'Owner' tag (bucket has no tags)")
                compliance_type = 'NON_COMPLIANT'
            else:
                # Other error accessing tags
                logger.warning(f"Error checking tags for {bucket_name}: {str(e)}")
                issues.append(f"Error checking tags: {error_code}")
                compliance_type = 'NON_COMPLIANT'
        
        # Check 2: Verify public access is fully blocked
        logger.info(f"Checking public access block settings for bucket: {bucket_name}")
        try:
            # Get public access block configuration
            public_access_response = s3_client.get_public_access_block(Bucket=bucket_name)
            public_access_config = public_access_response.get('PublicAccessBlockConfiguration', {})
            
            # All four settings must be True for full blocking
            block_public_acls = public_access_config.get('BlockPublicAcls', False)
            ignore_public_acls = public_access_config.get('IgnorePublicAcls', False)
            block_public_policy = public_access_config.get('BlockPublicPolicy', False)
            restrict_public_buckets = public_access_config.get('RestrictPublicBuckets', False)
            
            if not all([block_public_acls, ignore_public_acls, block_public_policy, restrict_public_buckets]):
                public_access_issues = []
                if not block_public_acls:
                    public_access_issues.append("BlockPublicAcls is False")
                if not ignore_public_acls:
                    public_access_issues.append("IgnorePublicAcls is False")
                if not block_public_policy:
                    public_access_issues.append("BlockPublicPolicy is False")
                if not restrict_public_buckets:
                    public_access_issues.append("RestrictPublicBuckets is False")
                
                issues.append(f"Public access not fully blocked: {', '.join(public_access_issues)}")
                compliance_type = 'NON_COMPLIANT'
            else:
                logger.info(f"Bucket {bucket_name} has public access fully blocked")
                
        except ClientError as e:
            error_code = e.response['Error']['Code']
            if error_code == 'NoSuchPublicAccessBlockConfiguration':
                # Public access block is not configured (default allows public access)
                issues.append("Public access block configuration not set (public access allowed)")
                compliance_type = 'NON_COMPLIANT'
            else:
                # Other error accessing public access block
                logger.warning(f"Error checking public access block for {bucket_name}: {str(e)}")
                issues.append(f"Error checking public access block: {error_code}")
                compliance_type = 'NON_COMPLIANT'
        
        # Build annotation message
        if compliance_type == 'COMPLIANT':
            annotation = f"Bucket '{bucket_name}' is compliant: has Owner tag and public access is fully blocked."
        else:
            annotation = f"Bucket '{bucket_name}' is non-compliant: {'; '.join(issues)}"
        
        logger.info(f"Evaluation result for {bucket_name}: {compliance_type}")
        
    except Exception as e:
        # Handle any unexpected errors
        logger.error(f"Unexpected error evaluating bucket {bucket_name}: {str(e)}")
        compliance_type = 'NON_COMPLIANT'
        annotation = f"Error evaluating bucket '{bucket_name}': {str(e)}"
    
    return {
        'compliance_type': compliance_type,
        'annotation': annotation
    }


def lambda_handler(event, context):
    """
    AWS Lambda handler function for AWS Config custom rule.
    
    This function evaluates all S3 buckets in the account for compliance.
    A bucket is compliant if:
    1. It has a tag key "Owner"
    2. Public access is fully blocked
    
    Args:
        event: AWS Config event object containing:
            - invokingEvent: JSON string with configuration item
            - ruleParameters: Optional rule parameters
            - resultToken: Token for reporting results
            - eventLeftScope: Whether event is out of scope
        context: Lambda context object
    
    Returns:
        dict: AWS Config evaluation results in required format
    """
    try:
        logger.info("Starting S3 bucket compliance evaluation")
        logger.info(f"Event: {event}")
        
        # Parse the invoking event (only if present and not empty)
        invoking_event = event.get('invokingEvent', '')
        if isinstance(invoking_event, str) and invoking_event.strip():
            import json
            try:
                invoking_event = json.loads(invoking_event)
            except json.JSONDecodeError as e:
                logger.warning(f"Could not parse invokingEvent as JSON: {str(e)}")
                # Continue execution - we'll evaluate all buckets anyway
        elif not invoking_event:
            logger.info("No invokingEvent provided (likely manual test) - will evaluate all buckets")
        
        # Get the result token for reporting results
        result_token = event.get('resultToken', '')
        
        # Check if event is out of scope (resource deleted)
        event_left_scope = event.get('eventLeftScope', False)
        
        # List all S3 buckets in the account
        logger.info("Listing all S3 buckets in the account")
        buckets = []
        try:
            response = s3_client.list_buckets()
            buckets = [bucket['Name'] for bucket in response.get('Buckets', [])]
            logger.info(f"Found {len(buckets)} S3 bucket(s) to evaluate")
        except ClientError as e:
            error_code = e.response['Error']['Code']
            error_message = e.response['Error']['Message']
            logger.error(f"Error listing buckets: {error_code}: {error_message}")
            # Return error evaluation
            return {
                'error': f"Failed to list S3 buckets: {error_code}: {error_message}"
            }
        
        # Evaluate each bucket
        evaluations = []
        for bucket_name in buckets:
            logger.info(f"Evaluating bucket: {bucket_name}")
            evaluation_result = evaluate_s3_bucket(bucket_name)
            
            # Create evaluation in AWS Config format
            evaluation = {
                'ComplianceResourceType': 'AWS::S3::Bucket',
                'ComplianceResourceId': bucket_name,
                'ComplianceType': evaluation_result['compliance_type'],
                'Annotation': evaluation_result['annotation'],
                'OrderingTimestamp': datetime.utcnow().isoformat() + 'Z'
            }
            
            evaluations.append(evaluation)
        
        # Log summary
        compliant_count = sum(1 for e in evaluations if e['ComplianceType'] == 'COMPLIANT')
        non_compliant_count = len(evaluations) - compliant_count
        logger.info(f"Evaluation complete: {compliant_count} compliant, {non_compliant_count} non-compliant")
        
        # Report results back to AWS Config
        if result_token:
            try:
                # AWS Config has a limit of 100 evaluations per PutEvaluations call
                # Split evaluations into batches of 100
                batch_size = 100
                for i in range(0, len(evaluations), batch_size):
                    batch = evaluations[i:i + batch_size]
                    logger.info(f"Reporting batch {i//batch_size + 1} with {len(batch)} evaluations to AWS Config")
                    
                    response = config_client.put_evaluations(
                        Evaluations=batch,
                        ResultToken=result_token
                    )
                    logger.info(f"Successfully reported batch to AWS Config: {response}")
                    
            except ClientError as e:
                error_code = e.response['Error']['Code']
                error_message = e.response['Error']['Message']
                logger.error(f"Error reporting evaluations to AWS Config: {error_code}: {error_message}")
                raise
        else:
            logger.warning("No resultToken provided - cannot report evaluations to AWS Config (likely a test invocation)")
        
        # Return results for testing/debugging purposes
        return {
            'evaluations': evaluations,
            'compliant_count': compliant_count,
            'non_compliant_count': non_compliant_count
        }
        
    except Exception as e:
        error_msg = f"Unexpected error in lambda_handler: {str(e)}"
        logger.error(error_msg, exc_info=True)
        return {
            'error': error_msg
        }

