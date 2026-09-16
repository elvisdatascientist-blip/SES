# AWS SES Quota Visibility & Per-Sender Monitoring

**Account:** mohcluster (024848484634)
**Region:** eu-west-2 (London)
**Domain:** tiberbu.health
**Daily Quota:** 50,000 emails / 24h rolling window
**Incident Date:** 2026-09-15 — quota exceeded, cause unknown (no CloudTrail trail was configured)

---

## Background

We share one SES account across 53 IAM users (47 counties + 6 app users).
All 53 share the **same 50,000/day quota** — any single sender can exhaust it for everyone.

On 2026-09-15 we exceeded the quota. Because no CloudTrail trail existed at the time,
we could not determine which user caused the spike. This runbook sets up:

1. **CloudTrail** — so every SES API call is logged going forward
2. **Configuration Sets + CloudWatch Log Groups** — per-sender visibility in near real-time
3. **CloudWatch Alarms** — alert before we hit the limit again

---

## Step 1: Verify Current Quota Usage

**What this does:** Checks how many emails have been sent in the last 24 hours
against your daily limit. The window is rolling (not midnight-reset).

```bash
aws sesv2 get-account \
  --profile mohcluster \
  --region eu-west-2 \
  --query 'SendQuota'
```

**Expected output:**
```json
{
    "Max24HourSend": 50000.0,
    "MaxSendRate": 14.0,
    "SentLast24Hours": 17154.0
}
```

- `Max24HourSend` — your ceiling
- `SentLast24Hours` — emails sent in the last rolling 24 hours
- `MaxSendRate` — max emails per second

---

## Step 2: Audit IAM Users with SES Access

**What this does:** Lists all IAM users that have SES permissions attached,
and what policy grants them access. This is how we identified all 53 senders.

```bash
# List all IAM users
aws iam list-users \
  --profile mohcluster \
  --output json \
  --query 'Users[*].UserName'

# Check policies for a specific user
aws iam list-attached-user-policies \
  --profile mohcluster \
  --user-name hmis-nairobi-SES

aws iam list-user-policies \
  --profile mohcluster \
  --user-name hmis-nairobi-SES
```

### Findings: SES IAM Users (53 total)

**Category 1: HMIS per-county (47 users)**

All have `AmazonSESFullAccess` managed policy attached.

| IAM User | County | Notes |
|---|---|---|
| hmis-baringo-SES | Baringo | |
| hmis-bomet-SES | Bomet | |
| hmis-bungoma-SES | Bungoma | |
| hmis-busia-SES | Busia | |
| hmis-elgeyo-marakwet-SES | Elgeyo Marakwet | |
| hmis-embu-SES | Embu | |
| hmis-garissa-SES | Garissa | |
| hmis-isiolo-SES | Isiolo | |
| hmis-kajiado-SES | Kajiado | |
| hmis-kakamega-SES | Kakamega | |
| hmis-kericho-SES | Kericho | |
| hmis-kiambu-SES | Kiambu | |
| hmis-kirinyaga-SES | Kirinyaga | |
| hmis-kisii-SES | Kisii | |
| hmis-kisumu-SES | Kisumu | |
| hmis-kitui-SES | Kitui | |
| hmis-kwale-SES | Kwale | |
| hmis-laikipia-SES | Laikipia | |
| hmis-lamu-SES | Lamu | |
| hmis-machakos-SES | Machakos | |
| hmis-makueni-SES | Makueni | |
| hmis-mandera-SES | Mandera | |
| hmis-marsabit-SES | Marsabit | |
| hmis-meru-SES | Meru | |
| hmis-migori-SES | Migori | |
| hmis-mombasa-SES | Mombasa | |
| hmis-muranga-SES | Murang'a | |
| hmis-nairobi-SES | Nairobi | |
| hmis-nakuru-SES | Nakuru | |
| hmis-nandi-SES | Nandi | |
| hmis-narok-SES | Narok | |
| hmis-nyamira-SES | Nyamira | |
| hmis-nyandarua-SES | Nyandarua | |
| hmis-nyeri-SES | Nyeri | |
| hmis-samburu-SES | Samburu | |
| hmis-taita-taveta-SES | Taita Taveta | |
| hmis-tana-river-SES | Tana River | |
| hmis-tharaka-nithi-SES | Tharaka Nithi | |
| hmis-transnzoia-SES | Trans Nzoia | |
| hmis-turkana-SES | Turkana | |
| hmis-uasin-gishu-SES | Uasin Gishu | |
| hmis-uat-SES | UAT environment | Has extra inline policy: `DenyOutsideClusterIP` |
| hmis-vihiga-SES | Vihiga | |
| hmis-wajir-SES | Wajir | |
| hmis-west-pokot-SES | West Pokot | |

**Category 2: App/Service users (6 users)**

| IAM User | App | Policy |
|---|---|---|
| client-registry-SES | Client Registry (prod) | AmazonSESFullAccess |
| client-registry-uat-SES | Client Registry (UAT) | AmazonSESFullAccess |
| compliance360-SES | Compliance360 | AmazonSESFullAccess |
| ses-smtp | Generic SMTP sender | AmazonSESFullAccess |
| simple-email-service | Generic SES sender | AmazonSESFullAccess |
| SHRAPPPROD | SHRAPP (prod) | AmazonHealthLakeFullAccess (NOT SES) |
| SHRAPPUAT | SHRAPP (UAT) | AmazonHealthLakeFullAccess (NOT SES) |

> **Note:** `SHRAPPPROD` and `SHRAPPUAT` do NOT have SES permissions — they are HealthLake users,
> not email senders. They can be removed from the SES investigation.

**Effective SES senders: 51 users** (47 county HMIS + 4 app users)

---

## Step 3: Set Up CloudTrail (One-Time)

**Why:** Without a CloudTrail trail, AWS only keeps 90 days of limited event history
and you cannot query who sent what. A trail writes every API call to S3 permanently.

**What this does — broken down:**

```bash
# 3a. Create an S3 bucket to store the logs
# Replace <unique-suffix> with something like your account ID or date
aws s3api create-bucket \
  --profile mohcluster \
  --bucket tiberbu-cloudtrail-logs-024848484634 \
  --region eu-west-2 \
  --create-bucket-configuration LocationConstraint=eu-west-2
```
> This creates a private S3 bucket. CloudTrail will write compressed JSON logs here.
> Each log file = all API calls in a 5-minute window.

```bash
# 3b. Create the trail (multi-region = captures ALL regions, not just London)
aws cloudtrail create-trail \
  --profile mohcluster \
  --region eu-west-2 \
  --name tiberbu-main-trail \
  --s3-bucket-name tiberbu-cloudtrail-logs-024848484634 \
  --is-multi-region-trail \
  --include-global-service-events
```
> `--is-multi-region-trail` — catches calls made to SES even if someone accidentally
> targets a different region.
> `--include-global-service-events` — captures IAM events too (useful for security audits).

```bash
# 3c. Start logging (trail is created paused by default)
aws cloudtrail start-logging \
  --profile mohcluster \
  --region eu-west-2 \
  --name tiberbu-main-trail
```

```bash
# 3d. Verify it is running
aws cloudtrail get-trail-status \
  --profile mohcluster \
  --region eu-west-2 \
  --name tiberbu-main-trail \
  --query '{IsLogging:IsLogging, LatestDelivery:LatestDeliveryTime}'
```
> `IsLogging` should be `true`. `LatestDeliveryTime` will populate after the first
> 5-minute window passes.

---

## Step 4: Create CloudWatch Log Groups

**Why:** We create two log groups — one for all HMIS counties, one for non-HMIS apps.
This keeps logs organized and lets you query "how many emails did Nairobi county send
in the last hour?" using CloudWatch Logs Insights.

```bash
# For all HMIS county senders
aws logs create-log-group \
  --profile mohcluster \
  --region eu-west-2 \
  --log-group-name /aws/ses/hmis-counties

# For app/service senders (client-registry, compliance360, etc.)
aws logs create-log-group \
  --profile mohcluster \
  --region eu-west-2 \
  --log-group-name /aws/ses/apps

# Set retention to 90 days (so logs don't grow forever)
aws logs put-retention-policy \
  --profile mohcluster \
  --region eu-west-2 \
  --log-group-name /aws/ses/hmis-counties \
  --retention-in-days 90

aws logs put-retention-policy \
  --profile mohcluster \
  --region eu-west-2 \
  --log-group-name /aws/ses/apps \
  --retention-in-days 90
```

---

## Step 5: Create Configuration Sets

**What is a Configuration Set?**
A named tag you attach to SES API calls. SES uses it to route event data
(sent, bounced, delivered, complained) to a destination like CloudWatch Logs.

Without a config set, SES sends the email but records nothing per-sender.
With a config set, every send event is written to your log group with the sender tag.

```bash
# Config set for all HMIS county instances
aws sesv2 create-configuration-set \
  --profile mohcluster \
  --region eu-west-2 \
  --configuration-set-name cfgset-hmis-counties

# Config set for client-registry
aws sesv2 create-configuration-set \
  --profile mohcluster \
  --region eu-west-2 \
  --configuration-set-name cfgset-client-registry

# Config set for compliance360
aws sesv2 create-configuration-set \
  --profile mohcluster \
  --region eu-west-2 \
  --configuration-set-name cfgset-compliance360

# Config set for ses-smtp / simple-email-service (generic senders)
aws sesv2 create-configuration-set \
  --profile mohcluster \
  --region eu-west-2 \
  --configuration-set-name cfgset-generic-smtp
```

---

## Step 6: Wire Configuration Sets to Log Groups

**What this does:** Tells each config set to write all email events
(Send, Bounce, Complaint, Delivery) into the appropriate CloudWatch Log Group.

```bash
# HMIS counties → /aws/ses/hmis-counties
aws sesv2 create-configuration-set-event-destination \
  --profile mohcluster \
  --region eu-west-2 \
  --configuration-set-name cfgset-hmis-counties \
  --event-destination-name logs-dest \
  --event-destination '{
    "Enabled": true,
    "MatchingEventTypes": ["SEND","BOUNCE","COMPLAINT","DELIVERY","REJECT"],
    "CloudWatchLogsDestination": {
      "LogGroupArn": "arn:aws:logs:eu-west-2:024848484634:log-group:/aws/ses/hmis-counties"
    }
  }'

# Apps → /aws/ses/apps
aws sesv2 create-configuration-set-event-destination \
  --profile mohcluster \
  --region eu-west-2 \
  --configuration-set-name cfgset-client-registry \
  --event-destination-name logs-dest \
  --event-destination '{
    "Enabled": true,
    "MatchingEventTypes": ["SEND","BOUNCE","COMPLAINT","DELIVERY","REJECT"],
    "CloudWatchLogsDestination": {
      "LogGroupArn": "arn:aws:logs:eu-west-2:024848484634:log-group:/aws/ses/apps"
    }
  }'

# Repeat for cfgset-compliance360 and cfgset-generic-smtp
# (same command, change --configuration-set-name)
```

---

## Step 7: Update App Code to Use Configuration Sets

**This is the most important step.** Until apps pass the config set name in
their SES API call, none of the above logging takes effect.

### How SES knows which config set to use

The app must include `ConfigurationSetName` in the API call. Example:

**Python (boto3):**
```python
ses.send_email(
    Source='noreply@tiberbu.health',
    Destination={'ToAddresses': ['user@example.com']},
    Message={...},
    ConfigurationSetName='cfgset-hmis-counties',   # <-- this line
    Tags=[{'Name': 'County', 'Value': 'nairobi'}]  # optional: per-county tag
)
```

**SMTP (e.g. Frappe/ERPNext):**
Add this header to every outgoing email:
```
X-SES-CONFIGURATION-SET: cfgset-hmis-counties
```
In Frappe, this is set in: `Site Config → email_account → ses_configuration_set`

### County-level tagging (recommended)

Since all 47 counties share one config set (`cfgset-hmis-counties`), add an
email tag so you can filter by county in CloudWatch Logs Insights:

```python
Tags=[{'Name': 'County', 'Value': 'nairobi'}]
```

Or via SMTP header:
```
X-SES-MESSAGE-TAGS: County=nairobi
```

---

## Step 8: CloudWatch Logs Insights Queries

Once logs are flowing, use these queries in the CloudWatch console
(**CloudWatch → Logs → Logs Insights**, select the log group).

**Total sends per county (last 24h):**
```
fields @timestamp, mail.tags.County.0, eventType
| filter eventType = "Send"
| stats count() as TotalSent by mail.tags.County.0
| sort TotalSent desc
```

**Hourly send rate (spot the spike):**
```
fields @timestamp, eventType
| filter eventType = "Send"
| stats count() as Sends by bin(1h)
| sort @timestamp asc
```

**Bounces and complaints by sender:**
```
fields @timestamp, mail.tags.County.0, eventType
| filter eventType in ["Bounce", "Complaint"]
| stats count() as Issues by mail.tags.County.0, eventType
| sort Issues desc
```

---

## Step 9: CloudWatch Alarm — Alert Before Quota Is Hit

**What this does:** Sends an SNS alert when SES sends exceed 40,000 in 24h
(80% of quota) — giving you time to investigate before hitting the ceiling.

> Note: SES does not publish a native "SentLast24Hours" CloudWatch metric.
> The alarm below triggers on the per-minute send rate sustained over time.
> For a more direct approach, a Lambda that calls `sesv2 get-account` on a
> schedule and publishes a custom metric is the cleanest solution — we can
> add that as a follow-up step.

```bash
# Create SNS topic for alerts
aws sns create-topic \
  --profile mohcluster \
  --region eu-west-2 \
  --name ses-quota-alerts

# Subscribe your email to the topic (replace with your address)
aws sns subscribe \
  --profile mohcluster \
  --region eu-west-2 \
  --topic-arn arn:aws:sns:eu-west-2:024848484634:ses-quota-alerts \
  --protocol email \
  --notification-endpoint devops@tiberbu.com
```

---

## Summary: What Each Piece Does

| Component | What It Does | When It Helps |
|---|---|---|
| **CloudTrail trail** | Records every AWS API call (including `ses:SendEmail`) to S3 | Post-incident forensics, audit |
| **CloudWatch Log Groups** | Stores structured SES event data (sent/bounce/complaint) | Real-time queries via Logs Insights |
| **Configuration Sets** | Tags email traffic so SES knows which log group to write to | Links sends to a named sender |
| **Email Tags (County=X)** | Further breaks down HMIS county traffic within one config set | County-level attribution |
| **CloudWatch Alarm** | Alerts at 80% quota usage | Prevents repeat of the incident |

---

## Current Status

| Step | Status | Notes |
|---|---|---|
| Quota audit | Done | 17,154 / 50,000 as of 2026-09-16 |
| IAM user audit | Done | 51 active SES senders identified |
| CloudTrail trail | Pending | |
| CloudWatch Log Groups | Pending | |
| Configuration Sets | Pending | |
| App code updates | Pending | Need to coordinate with county HMIS teams |
| CloudWatch Alarm | Pending | |

---

## Key Contacts / Ownership

| Sender Group | Owner / Team |
|---|---|
| hmis-{county}-SES (47 users) | County HMIS teams / MOH |
| client-registry-SES | Client Registry team |
| compliance360-SES | Compliance360 team |
| ses-smtp / simple-email-service | Platform team (generic) |

---

*Document created: 2026-09-16*
*Author: Platform/Security Engineering — Elvis*
