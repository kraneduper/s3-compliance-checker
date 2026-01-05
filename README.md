# AWS Config Custom Rule: S3 Bucket Compliance

An AWS Config custom rule Lambda function that evaluates S3 buckets for compliance with organizational policies. This rule checks that all S3 buckets have proper tagging (Owner tag) and public access blocking configured.

## 📋 Overview

This Lambda function serves as a custom AWS Config rule that automatically evaluates all S3 buckets in your AWS account for compliance. A bucket is considered compliant if:
1. It has a tag with the key "Owner"
2. Public access is fully blocked (all four public access block settings enabled)

## ✨ Features

- **Automated Compliance Evaluation**: Evaluates all S3 buckets in the account automatically
- **Comprehensive Checks**: Validates both tagging and public access block configurations
- **Batch Reporting**: Handles large numbers of buckets by batching evaluations (100 per batch)
- **Detailed Annotations**: Provides clear compliance annotations explaining why buckets are compliant or non-compliant
- **Error Handling**: Gracefully handles missing configurations, permissions errors, and other edge cases
- **CloudWatch Logging**: Full logging for monitoring, debugging, and audit trails
- **AWS Config Integration**: Seamlessly integrates with AWS Config for continuous compliance monitoring

## 🏗️ Architecture

```
AWS Config
    ↓
Lambda Function (Custom Rule)
    ↓
1. List All S3 Buckets
    ↓
2. For Each Bucket:
   - Check for "Owner" tag
   - Check public access block settings
    ↓
3. Generate Compliance Evaluations
    ↓
4. Report Results to AWS Config (batched)
    ↓
5. AWS Config Dashboard Shows Compliance Status
```

## 📦 Prerequisites

- AWS Account with AWS Config enabled
- Python 3.8+ (for local testing)
- AWS Lambda runtime environment
- boto3 library (included in Lambda runtime)
- AWS Config service enabled in your account/region

## 🔐 Required IAM Permissions

The Lambda execution role needs the following permissions:

```json
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
```

### Permission Details

- **s3:ListAllMyBuckets**: Required to enumerate all buckets in the account
- **s3:GetBucketTagging**: Required to check if buckets have the "Owner" tag
- **s3:GetBucketPublicAccessBlock**: Required to verify public access block settings
- **config:PutEvaluations**: Required to submit evaluation results back to AWS Config
- **logs:***: Required for CloudWatch Logs (standard Lambda logging permissions)

## 🚀 Deployment

### Step 1: Create the Lambda Function

1. Navigate to AWS Lambda Console
2. Click "Create function"
3. Choose "Author from scratch"
4. Configure:
   - **Function name**: `s3-bucket-compliance-rule` (or your preferred name)
   - **Runtime**: Python 3.8 or later
   - **Architecture**: x86_64
5. Click "Create function"

### Step 2: Upload the Code

1. Copy the contents of `custom-config-rule.py`
2. Paste into the Lambda function code editor
3. Click "Deploy"

### Step 3: Configure Execution Role

1. In the Lambda function, go to "Configuration" → "Permissions"
2. Click on the execution role
3. Attach the IAM policy with the permissions listed above
4. Or create a new role with the required permissions

### Step 4: Configure Lambda Settings

Recommended settings:
- **Timeout**: 5 minutes (for accounts with many buckets)
- **Memory**: 256 MB (minimum recommended)
- **Environment variables**: None required

### Step 5: Create AWS Config Custom Rule

1. Navigate to AWS Config Console
2. Go to "Rules" → "Add rule"
3. Select "Add custom rule"
4. Configure:
   - **Rule name**: `s3-bucket-owner-tag-and-public-access-block`
   - **Description**: "Checks that S3 buckets have Owner tag and public access blocked"
   - **Lambda function**: Select your Lambda function
   - **Trigger type**: 
     - **Configuration changes**: When S3 bucket configuration changes
     - **Periodic**: On a schedule (e.g., every 24 hours)
   - **Scope of changes**: Select "Resources" → "S3 Bucket"
5. Click "Save"

## 📝 Usage

### Automatic Evaluation

Once configured, AWS Config will automatically:
- Evaluate buckets when they are created or modified (if trigger type is "Configuration changes")
- Evaluate all buckets on a schedule (if trigger type is "Periodic")
- Display compliance results in the AWS Config dashboard

### Manual Evaluation

You can manually trigger an evaluation:

1. **Via AWS Config Console**:
   - Go to AWS Config → Rules
   - Select your custom rule
   - Click "Re-evaluate"

2. **Via Lambda Console** (for testing):
   - Go to Lambda function
   - Click "Test"
   - Use this test event:
   ```json
   {
       "invokingEvent": "",
       "ruleParameters": "",
       "resultToken": "",
       "eventLeftScope": false
   }
   ```

### Test Event (No resultToken)

For local testing without AWS Config integration:

```json
{
    "invokingEvent": "",
    "ruleParameters": "",
    "resultToken": "",
    "eventLeftScope": false
}
```

This will evaluate all buckets but won't report to AWS Config (useful for debugging).

## 📊 Compliance Rules

### Compliant Bucket

A bucket is **COMPLIANT** if:
- ✅ Has a tag with key "Owner" (value can be anything)
- ✅ Has public access block configuration with all four settings enabled:
  - `BlockPublicAcls = True`
  - `IgnorePublicAcls = True`
  - `BlockPublicPolicy = True`
  - `RestrictPublicBuckets = True`

### Non-Compliant Bucket

A bucket is **NON_COMPLIANT** if:
- ❌ Missing "Owner" tag (or bucket has no tags at all)
- ❌ Public access block not configured
- ❌ Public access block configured but not all settings are enabled
- ❌ Any error occurs during evaluation (treated as non-compliant for safety)

## 📈 Output

### Lambda Function Response

```json
{
    "evaluations": [
        {
            "ComplianceResourceType": "AWS::S3::Bucket",
            "ComplianceResourceId": "my-bucket-name",
            "ComplianceType": "COMPLIANT",
            "Annotation": "Bucket 'my-bucket-name' is compliant: has Owner tag and public access is fully blocked.",
            "OrderingTimestamp": "2025-01-15T14:30:52.123456Z"
        },
        {
            "ComplianceResourceType": "AWS::S3::Bucket",
            "ComplianceResourceId": "non-compliant-bucket",
            "ComplianceType": "NON_COMPLIANT",
            "Annotation": "Bucket 'non-compliant-bucket' is non-compliant: Missing 'Owner' tag; Public access block configuration not set (public access allowed)",
            "OrderingTimestamp": "2025-01-15T14:30:52.123456Z"
        }
    ],
    "compliant_count": 1,
    "non_compliant_count": 1
}
```

### AWS Config Dashboard

Results appear in the AWS Config dashboard:
- **Compliant resources**: Green checkmark
- **Non-compliant resources**: Red X
- **Compliance score**: Percentage of compliant buckets
- **Detailed annotations**: Click on a resource to see why it's compliant/non-compliant

## 🔍 Monitoring

### CloudWatch Logs

All execution logs are available in CloudWatch Logs:
- **Log group**: `/aws/lambda/<function-name>`
- **Log streams**: One per execution

Example log entries:
```
INFO: Starting S3 bucket compliance evaluation
INFO: Found 15 S3 bucket(s) to evaluate
INFO: Evaluating bucket: my-bucket-name
INFO: Bucket my-bucket-name has Owner tag with value: john.doe@example.com
INFO: Bucket my-bucket-name has public access fully blocked
INFO: Evaluation result for my-bucket-name: COMPLIANT
INFO: Evaluation complete: 12 compliant, 3 non-compliant
```

### AWS Config Compliance Dashboard

Monitor compliance in real-time:
- View overall compliance score
- See which buckets are non-compliant
- Review compliance history over time
- Set up CloudWatch alarms for compliance violations

## 🛠️ Error Handling

The function handles various error scenarios gracefully:

### Missing Tags
- **Scenario**: Bucket has no tags at all
- **Handling**: Detects `NoSuchTagSet` error and marks as non-compliant
- **Annotation**: "Missing 'Owner' tag (bucket has no tags)"

### Missing Public Access Block
- **Scenario**: Public access block not configured
- **Handling**: Detects `NoSuchPublicAccessBlockConfiguration` error
- **Annotation**: "Public access block configuration not set (public access allowed)"

### Partial Public Access Block
- **Scenario**: Public access block exists but not all settings enabled
- **Handling**: Checks each of the four settings individually
- **Annotation**: Lists which specific settings are disabled

### Permission Errors
- **Scenario**: Lambda role lacks required permissions
- **Handling**: Logs error and returns error response
- **Action**: Check IAM role permissions

### API Errors
- **Scenario**: AWS API errors (throttling, service issues)
- **Handling**: Logs error with full details
- **Action**: Check CloudWatch Logs for details

## 🐛 Troubleshooting

### Common Issues

1. **"Access Denied" Errors**
   - **Cause**: Lambda execution role missing required permissions
   - **Solution**: Verify all IAM permissions are attached to the Lambda role
   - **Check**: CloudWatch Logs for specific permission errors

2. **No Evaluations Reported**
   - **Cause**: Missing `resultToken` or AWS Config not properly configured
   - **Solution**: Ensure the rule is created in AWS Config and properly linked to the Lambda function
   - **Check**: AWS Config rule configuration

3. **Buckets Not Evaluated**
   - **Cause**: Lambda function not triggered or error during execution
   - **Solution**: Check CloudWatch Logs for execution errors
   - **Check**: AWS Config rule trigger configuration

4. **Timeout Errors**
   - **Cause**: Too many buckets to evaluate within timeout period
   - **Solution**: Increase Lambda timeout (recommended: 5 minutes)
   - **Note**: Function batches evaluations (100 per batch) to handle large numbers

5. **Incorrect Compliance Status**
   - **Cause**: Bucket configuration changed after evaluation
   - **Solution**: Re-evaluate the rule or wait for next scheduled evaluation
   - **Check**: Verify bucket tags and public access block settings manually

### Debugging Steps

1. **Check CloudWatch Logs**:
   ```bash
   aws logs tail /aws/lambda/<function-name> --follow
   ```

2. **Test Lambda Function Directly**:
   - Use Lambda console test feature
   - Review response for evaluation results

3. **Verify IAM Permissions**:
   - Check Lambda execution role
   - Test permissions with AWS CLI or IAM Policy Simulator

4. **Check AWS Config Rule**:
   - Verify rule is enabled
   - Check trigger configuration
   - Review rule evaluation history

## 📁 File Structure

```
.
├── custom-config-rule.py    # Main Lambda function code
└── README.md  # This file
```

## 🔄 Best Practices

1. **Regular Evaluations**: Set up periodic evaluations (daily recommended)
2. **Monitoring**: Set up CloudWatch alarms for non-compliant resources
3. **Automated Remediation**: Consider creating remediation actions for common issues
4. **Tagging Policy**: Enforce "Owner" tag at bucket creation using SCPs or IAM policies
5. **Public Access Block**: Consider enabling account-level public access block settings

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## 📄 License

This project is provided as-is for educational and compliance purposes.

## ⚠️ Important Notes

- **AWS Config Required**: This function requires AWS Config to be enabled in your account
- **Regional**: AWS Config rules are regional - deploy in each region where you need compliance checks
- **Cost**: AWS Config charges apply for configuration items and evaluations
- **Batch Limits**: AWS Config limits evaluations to 100 per `PutEvaluations` call (handled automatically)
- **Timeout**: For accounts with many buckets (>100), increase Lambda timeout accordingly
- **Tag Value**: The function only checks for the presence of the "Owner" tag key, not its value

## 📞 Support

For issues or questions, please open an issue in the repository or check AWS Config documentation.
